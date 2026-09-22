"""
JWTModule — GhostRecon module.
Analyzes JSON Web Tokens (JWT) for security misconfigurations.
"""
import re
import json
import base64

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class JWTModule(BaseModule):
    NAME = "JWT Analysis"

    JWT_REGEX = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

    def run(self):
        self.ui.section("JWT — JSON Web Token Security Analysis")
        if not requests:
            return

        # JWTs discovered from previous scans (stored in context if any, e.g., headers or local storage analysis)
        jwt_tokens = set()

        # Check endpoints to find JWTs in Set-Cookie or Authorization headers
        s = self._session()
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:10]
        
        for endpoint in endpoints:
            try:
                resp = s.get(endpoint, timeout=self.timeout)
                # Check response body
                for match in re.finditer(self.JWT_REGEX, resp.text):
                    jwt_tokens.add(match.group(0))
                # Check headers
                for k, v in resp.headers.items():
                    for match in re.finditer(self.JWT_REGEX, v):
                        jwt_tokens.add(match.group(0))
            except Exception:
                pass

        if not jwt_tokens:
            self.ui.info("No JWT tokens discovered.")
            return

        self.ui.info(f"Discovered {len(jwt_tokens)} JWT(s) for analysis.")

        for token in jwt_tokens:
            self._analyze_jwt(token)

    def _pad_base64(self, data: str) -> str:
        """Add padding to base64 string if necessary."""
        return data + '=' * (4 - len(data) % 4)

    def _analyze_jwt(self, token: str):
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
        
        # 1. Check for 'none' algorithm
        if alg == 'NONE':
            self.db.add(
                title="JWT — 'none' Algorithm Accepted",
                severity="critical", url=self.base_url, module=self.NAME,
                description=(
                    "The JWT header uses the 'none' algorithm, indicating it lacks cryptographic signature. "
                    "If the server accepts this token, an attacker can modify the payload to escalate privileges."
                ),
                remediation="Reject JWTs with the 'none' algorithm. Always enforce signature verification.",
                cvss="9.1",
                confidence="MEDIUM", # We detected it, but didn't exploit it
                confidence_score=60,
                validation_steps=["jwt_parsed", "alg_none_detected"]
            )
            self.ui.find("critical", "JWT 'none' Algorithm", self.base_url)

        # 2. Check for missing expiration
        if 'exp' not in payload:
            self.db.add(
                title="JWT — Missing Expiration (exp) Claim",
                severity="medium", url=self.base_url, module=self.NAME,
                description="The JWT payload does not contain an 'exp' claim. The token never expires.",
                remediation="Include a short-lived 'exp' claim in all JWTs.",
                cvss="5.3",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["jwt_parsed", "exp_missing"]
            )
            self.ui.find("medium", "JWT Missing exp claim", self.base_url)

        # 3. Check for sensitive data in payload
        sensitive_keys = ['password', 'pwd', 'ssn', 'credit_card', 'secret', 'key']
        found_sensitive = [k for k in payload.keys() if any(sk in k.lower() for sk in sensitive_keys)]
        
        if found_sensitive:
            self.db.add(
                title="JWT — Sensitive Data in Payload",
                severity="high", url=self.base_url, module=self.NAME,
                description=(
                    f"The JWT payload contains potentially sensitive fields: {', '.join(found_sensitive)}. "
                    "JWT payloads are base64 encoded, not encrypted, and can be read by anyone."
                ),
                remediation="Never store sensitive information in JWT payloads. Use opaque tokens if necessary.",
                cvss="7.4",
                confidence="HIGH",
                confidence_score=90,
                validation_steps=["jwt_parsed", "sensitive_keys_matched"],
                evidence=[f"Payload: {payload_json}"]
            )
            self.ui.find("high", "JWT Sensitive Data Exposure", self.base_url)
