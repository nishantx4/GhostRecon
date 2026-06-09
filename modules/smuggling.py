"""
SmugglingModule — GhostRecon module.
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


class SmugglingModule(BaseModule):
    NAME = "HTTP Smuggling"

    def run(self):
        self.ui.section("HTTP Request Smuggling — Passive Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        # Passive: check for proxy/load balancer headers that may indicate vuln infra
        resp = self._get(self.base_url)
        if not resp:
            return

        h = {k.lower(): v for k, v in resp.headers.items()}
        proxy_indicators = ["x-forwarded-for", "via", "x-varnish", "x-cache",
                            "cf-ray", "x-amz-cf-id", "x-cdn"]
        has_proxy = any(p in h for p in proxy_indicators)

        if has_proxy:
            self.db.add(
                title="HTTP Request Smuggling — Proxy Infrastructure Detected",
                severity="info", url=self.base_url, module=self.NAME,
                description=(
                    "A proxy/CDN layer is detected in front of the application. "
                    "This infrastructure is potentially vulnerable to HTTP request smuggling (CL.TE or TE.CL). "
                    "Manual testing with Burp Suite HTTP Request Smuggler extension is recommended."
                ),
                remediation=(
                    "Test with Burp HTTP Request Smuggler. Ensure front-end and back-end servers "
                    "consistently parse Transfer-Encoding and Content-Length headers."
                ),
                cvss="0.0", confidence="low",
            )
            self.ui.info("Proxy infrastructure detected — manual smuggling test recommended")
        else:
            self.ui.info("No proxy layer detected — smuggling risk lower")


# ─── CORS Module ───────────────────────────────────────────────────────────────