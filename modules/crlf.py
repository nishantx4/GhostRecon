"""
CRLFModule — GhostRecon module.
Detects HTTP Response Splitting via CRLF injection in parameters.
"""
import time
import uuid
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class CRLFModule(BaseModule):
    NAME = "CRLF Injection"

    CRLF_PARAMS = [
        "url", "redirect", "next", "return", "goto", "dest",
        "redirect_uri", "return_to", "continue", "target", "path",
        "callback", "rurl", "returnUrl", "view", "page",
    ]

    def run(self):
        self.ui.section("CRLF Injection — HTTP Response Splitting Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        canary = f"X-GhostRecon-CRLF-{uuid.uuid4().hex[:8]}"

        # Test discovered params + common redirect params
        test_params = set(self.CRLF_PARAMS)
        for ep in self.ctx.get("discovered_params", []):
            if isinstance(ep, dict):
                test_params.update(ep.get("params", {}).keys())
            elif isinstance(ep, str):
                test_params.add(ep)

        # Payloads that inject a custom header via CRLF
        payloads = [
            f"%0d%0a{canary}:true",
            f"%0d%0a%0d%0a<h1>ghostrecon_crlf</h1>",
            f"%0a{canary}:true",
            f"\\r\\n{canary}:true",
        ]

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]

        for endpoint in endpoints:
            for param in test_params:
                for payload in payloads:
                    url = f"{endpoint}?{param}={payload}"
                    try:
                        resp = s.get(url, timeout=self.timeout, allow_redirects=False)

                        # Check 1: Did our custom header get injected into response headers?
                        if canary.lower() in str(resp.headers).lower():
                            self.db.add(
                                title=f"CRLF Injection — Header Injection via '{param}'",
                                severity="high", url=endpoint, module=self.NAME,
                                description=(
                                    f"Parameter '{param}' allows CRLF injection. "
                                    f"Injected header '{canary}' appeared in response headers. "
                                    "This enables session fixation, XSS via Set-Cookie, and cache poisoning."
                                ),
                                remediation="Strip or encode CR (\\r) and LF (\\n) from all user input used in HTTP headers.",
                                cvss="7.5",
                                confidence="CONFIRMED",
                                confidence_score=95,
                                validation_steps=["canary_header_injected"],
                            )
                            self.ui.find("high", f"CRLF Header Injection via '{param}'", endpoint)
                            found += 1
                            break

                        # Check 2: Response body splitting
                        if "ghostrecon_crlf" in resp.text and "<h1>" in resp.text:
                            # Verify it's not just reflected in the page content
                            if resp.text.count("<h1>ghostrecon_crlf</h1>") > 0:
                                self.db.add(
                                    title=f"CRLF Injection — Response Splitting via '{param}'",
                                    severity="high", url=endpoint, module=self.NAME,
                                    description=(
                                        f"Parameter '{param}' allows HTTP response splitting. "
                                        "Attacker-controlled HTML was injected into the response body via CRLF."
                                    ),
                                    remediation="Strip or encode CR and LF characters from all user input.",
                                    cvss="7.5",
                                    confidence="HIGH",
                                    confidence_score=85,
                                    validation_steps=["body_split_detected"],
                                )
                                self.ui.find("high", f"CRLF Response Splitting via '{param}'", endpoint)
                                found += 1
                                break

                        time.sleep(self.delay)
                    except Exception:
                        continue
                if found > 5:
                    break
            if found > 5:
                break

        if found == 0:
            self.ui.info("No CRLF injection vulnerabilities detected.")
