"""
OpenRedirectModule — GhostRecon module.
Detects unvalidated redirect/forward vulnerabilities.
"""
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class OpenRedirectModule(BaseModule):
    NAME = "Open Redirect"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "goto", "dest",
        "redirect_uri", "return_to", "continue", "target", "rurl",
        "returnUrl", "forward", "follow", "redirect_url", "return_url",
        "checkout_url", "login_url", "image_url", "success_url",
    ]

    CANARY_URLS = [
        "//ghostrecon-redirect-test.example.com",
        "https://ghostrecon-redirect-test.example.com",
        "/\\ghostrecon-redirect-test.example.com",
        "//ghostrecon-redirect-test.example.com%2f%2f",
        "https://ghostrecon-redirect-test.example.com@{target}",
        "////ghostrecon-redirect-test.example.com",
        "https:ghostrecon-redirect-test.example.com",
    ]

    def run(self):
        self.ui.section("Open Redirect — Unvalidated Redirect Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        canary_domain = "ghostrecon-redirect-test.example.com"

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]

        for endpoint in endpoints:
            for param in self.REDIRECT_PARAMS:
                for canary_url in self.CANARY_URLS:
                    # Replace {target} placeholder with actual target
                    test_url = canary_url.replace("{target}", self.target)
                    full_url = f"{endpoint}?{param}={urllib.parse.quote(test_url, safe='')}"

                    try:
                        resp = s.get(full_url, timeout=self.timeout, allow_redirects=False)

                        # Check for redirect to our canary domain
                        location = resp.headers.get("Location", "")

                        if canary_domain in location:
                            self.db.add(
                                title=f"Open Redirect via '{param}' Parameter",
                                severity="medium", url=endpoint, module=self.NAME,
                                description=(
                                    f"Parameter '{param}' allows unvalidated redirects. "
                                    f"Injected URL '{test_url}' caused redirect to: {location}. "
                                    "This enables phishing, OAuth token theft, and SSO bypass attacks."
                                ),
                                remediation=(
                                    "Validate redirect targets against a whitelist of allowed domains. "
                                    "Use relative paths only, or maintain a mapping of allowed redirect keys."
                                ),
                                cvss="6.1",
                                confidence="CONFIRMED",
                                confidence_score=95,
                                validation_steps=["canary_in_location_header"],
                                evidence=[f"Location: {location}", f"Payload: {test_url}"],
                            )
                            self.ui.find("medium", f"Open Redirect via '{param}'", endpoint)
                            found += 1
                            break  # Found on this param, try next param

                        time.sleep(self.delay)
                    except Exception:
                        continue

                if found > 10:
                    break
            if found > 10:
                break

        if found == 0:
            self.ui.info("No open redirect vulnerabilities detected.")
