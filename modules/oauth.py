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
            
            # Check for missing state parameter
            if "client_id" in params and "redirect_uri" in params and "state" not in params:
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
                
        if found == 0:
             self.ui.info("No OAuth vulnerabilities detected.")
