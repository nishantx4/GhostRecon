"""
HeadersModule — GhostRecon module.
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


class HeadersModule(BaseModule):
    NAME = "Security Headers"

    REQUIRED_HEADERS = {
        "Strict-Transport-Security": ("high",   "9.0", "Missing HSTS allows downgrade attacks"),
        "Content-Security-Policy":   ("high",   "7.5", "Missing CSP enables XSS escalation"),
        "X-Frame-Options":           ("medium", "6.5", "Missing X-Frame-Options allows clickjacking"),
        "X-Content-Type-Options":    ("low",    "5.0", "Missing X-Content-Type-Options allows MIME sniffing"),
        "Referrer-Policy":           ("low",    "4.0", "Missing Referrer-Policy may leak sensitive URLs"),
        "Permissions-Policy":        ("info",   "3.0", "Missing Permissions-Policy — browser features uncontrolled"),
    }

    DANGEROUS_HEADERS = {
        "X-Powered-By":   ("info", "Reveals server technology stack"),
        "Server":         ("info", "Reveals server software and version"),
        "X-AspNet-Version": ("info", "Reveals ASP.NET version"),
    }

    def run(self):
        self.ui.section("Security Headers Analysis")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        resp = self._get(self.base_url)
        if not resp:
            self.ui.error(f"Could not reach {self.base_url}")
            return

        headers = {k.lower(): v for k, v in resp.headers.items()}

        for header, (severity, cvss, impact) in self.REQUIRED_HEADERS.items():
            if header.lower() not in headers:
                self.db.add(
                    title=f"Missing Security Header: {header}",
                    severity=severity,
                    url=self.base_url,
                    module=self.NAME,
                    description=f"The {header} HTTP response header is not set. {impact}.",
                    remediation=f"Add the '{header}' header to all responses.",
                    cvss=cvss,
                    confidence="high",
                )
                self.ui.find(severity, f"Missing: {header}", self.base_url)

        # Check for information disclosure headers
        for header, (severity, desc) in self.DANGEROUS_HEADERS.items():
            if header.lower() in headers:
                val = headers[header.lower()]
                self.db.add(
                    title=f"Information Disclosure: {header}: {val}",
                    severity=severity,
                    url=self.base_url,
                    module=self.NAME,
                    description=f"Response header '{header}: {val}' discloses server technology.",
                    remediation=f"Remove or obscure the '{header}' response header.",
                    confidence="high",
                )

        # Check for insecure cookies
        if "set-cookie" in headers:
            cookie = headers["set-cookie"]
            if "httponly" not in cookie.lower():
                self.db.add(
                    title="Session Cookie Missing HttpOnly Flag",
                    severity="medium", url=self.base_url, module=self.NAME,
                    description="Session cookie lacks HttpOnly flag — accessible to JavaScript (XSS theft).",
                    remediation="Set HttpOnly flag on all session cookies.",
                    cvss="5.4", confidence="high",
                )
                self.ui.find("medium", "Cookie missing HttpOnly", self.base_url)
            if "secure" not in cookie.lower():
                self.db.add(
                    title="Session Cookie Missing Secure Flag",
                    severity="medium", url=self.base_url, module=self.NAME,
                    description="Session cookie lacks Secure flag — transmitted over HTTP.",
                    remediation="Set Secure flag on all session cookies.",
                    cvss="5.4", confidence="high",
                )

        self.ui.ok("Headers analysis complete")


# ─── JS Analysis Module ───────────────────────────────────────────────────────