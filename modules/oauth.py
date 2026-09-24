"""
OAuthModule — GhostRecon module.
Detects OAuth 2.0 configuration flaws.
"""
import urllib.parse
try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class OAuthModule(BaseModule):
    NAME = "OAuth Security"

    def run(self):
        self.ui.section("OAuth — Security Misconfiguration Detection")
        if not requests:
            return

        endpoints = self.ctx.get("endpoints", [])
        oauth_endpoints = []
        
        # Identify OAuth endpoints
        for ep in endpoints:
            if any(x in ep.lower() for x in ["oauth", "authorize", "callback", "client_id", "redirect_uri"]):
                oauth_endpoints.append(ep)

        if not oauth_endpoints:
            self.ui.info("No OAuth endpoints discovered.")
            return

        found = 0

        for ep in oauth_endpoints:
            parsed = urllib.parse.urlparse(ep)
            params = urllib.parse.parse_qs(parsed.query)
            is_auth_request = "client_id" in params and "redirect_uri" in params
            if not is_auth_request:
                continue

            # Check for missing state parameter
            if "state" not in params:
                self.db.add(
                    title="OAuth — Missing 'state' Parameter",
                    severity="high", url=ep, module=self.NAME,
                    description=(
                        "The OAuth authorization request is missing the 'state' parameter. "
                        "This makes the OAuth flow vulnerable to Cross-Site Request Forgery (CSRF)."
                    ),
                    remediation="Always use a cryptographically strong, unguessable 'state' parameter to prevent CSRF.",
                    cvss="7.4",
                    confidence="HIGH",
                    confidence_score=85,
                    validation_steps=["oauth_endpoint_identified", "state_param_missing"]
                )
                self.ui.find("high", "OAuth Missing 'state' Parameter", ep)
                found += 1

            response_type = (params.get("response_type", [""])[0]).lower()

            # Implicit flow (response_type=token) returns the access token
            # directly in the URL fragment — leaks via browser history,
            # Referer headers, and any embedded/proxy JS. Deprecated by
            # OAuth 2.1 in favor of Authorization Code + PKCE.
            if response_type == "token":
                self.db.add(
                    title="OAuth — Deprecated Implicit Grant Flow",
                    severity="medium", url=ep, module=self.NAME,
                    description=(
                        "This authorization request uses response_type=token (the OAuth 2.0 "
                        "implicit grant). The access token is returned directly in the URL "
                        "fragment, exposing it to browser history, Referer leakage, and any "
                        "script with DOM access. OAuth 2.1 removes this grant entirely."
                    ),
                    remediation="Migrate to the Authorization Code flow with PKCE (response_type=code + code_challenge).",
                    cvss="5.4",
                    confidence="HIGH",
                    confidence_score=90,
                    validation_steps=["oauth_endpoint_identified", "implicit_flow_detected"],
                )
                self.ui.find("medium", "OAuth Implicit Grant Flow (deprecated)", ep)
                found += 1

            # Missing PKCE on an authorization-code request for a client that
            # looks public (no client_secret in this URL — a confidential
            # server-side client wouldn't leak its secret in the browser URL
            # either way, so absence here isn't conclusive on its own, hence
            # MEDIUM confidence rather than HIGH).
            elif response_type in ("code", "") and "code_challenge" not in params:
                self.db.add(
                    title="OAuth — Authorization Code Flow Without PKCE",
                    severity="medium", url=ep, module=self.NAME,
                    description=(
                        "The authorization request does not include a 'code_challenge' "
                        "(PKCE). Without PKCE, an attacker who intercepts the authorization "
                        "code (e.g. via a malicious app registering the same custom URI "
                        "scheme on mobile, or an open redirect) can exchange it for an "
                        "access token themselves."
                    ),
                    remediation="Implement PKCE (RFC 7636) for all public/native/SPA clients — send code_challenge and verify code_verifier on token exchange.",
                    cvss="6.5",
                    confidence="MEDIUM",
                    confidence_score=60,
                    validation_steps=["oauth_endpoint_identified", "pkce_param_missing"],
                )
                self.ui.find("medium", "OAuth Missing PKCE", ep)
                found += 1

        if found == 0:
             self.ui.info("No OAuth vulnerabilities detected.")
