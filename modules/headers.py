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
        if resp is None:
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

        # A header being PRESENT doesn't mean it's configured safely — these
        # checks catch the common case of a header existing but effectively
        # disabled or too permissive to provide real protection.
        hsts_val = headers.get("strict-transport-security", "")
        if hsts_val:
            m = re.search(r"max-age\s*=\s*(\d+)", hsts_val, re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age <= 0:
                self.db.add(
                    title="HSTS Present But Disabled (max-age=0)",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=f"Strict-Transport-Security is set (\"{hsts_val}\") but max-age is {max_age}, which disables HSTS enforcement entirely.",
                    remediation="Set Strict-Transport-Security max-age to at least 31536000 (1 year), ideally with includeSubDomains and preload.",
                    cvss="6.5", confidence="high",
                )
                self.ui.find("high", "HSTS present but disabled (max-age=0)", self.base_url)
            elif max_age < 15552000:  # < ~6 months
                self.db.add(
                    title="Weak HSTS max-age",
                    severity="low", url=self.base_url, module=self.NAME,
                    description=f"Strict-Transport-Security max-age is only {max_age}s (~{max_age // 86400} days), below the widely recommended 1-year minimum.",
                    remediation="Increase Strict-Transport-Security max-age to at least 31536000 seconds (1 year).",
                    cvss="3.1", confidence="medium",
                )
                self.ui.find("low", "Weak HSTS max-age", self.base_url)

        csp_val = headers.get("content-security-policy", "")
        if csp_val:
            csp_lower = csp_val.lower()
            weak_reasons = []
            if "unsafe-inline" in csp_lower:
                weak_reasons.append("allows 'unsafe-inline' (defeats CSP's main XSS mitigation)")
            if "unsafe-eval" in csp_lower:
                weak_reasons.append("allows 'unsafe-eval'")
            if re.search(r"(default-src|script-src)\s+[^;]*\*", csp_lower):
                weak_reasons.append("uses a wildcard (*) source on default-src/script-src")
            if weak_reasons:
                self.db.add(
                    title="Weak Content-Security-Policy",
                    severity="medium", url=self.base_url, module=self.NAME,
                    description=f"A CSP is present but weakened: {'; '.join(weak_reasons)}.",
                    remediation="Remove 'unsafe-inline'/'unsafe-eval' in favor of nonces or hashes for inline scripts, and avoid wildcard sources.",
                    cvss="5.4", confidence="high",
                    evidence=[f"CSP: {csp_val[:300]}"],
                )
                self.ui.find("medium", "Weak CSP (unsafe directives / wildcard sources)", self.base_url)

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
        # Need to properly parse Set-Cookie headers as there could be multiple
        if hasattr(resp, 'raw') and hasattr(resp.raw, 'headers') and hasattr(resp.raw.headers, 'getlist'):
            raw_cookies = resp.raw.headers.getlist('Set-Cookie')
        elif 'Set-Cookie' in resp.headers:
             # Requests merges them into one string if we just use resp.headers (bad for parsing)
             # Let's iterate through the session cookies if we can
             raw_cookies = [cookie.name + "=" + cookie.value for cookie in resp.cookies] if resp.cookies else []
             if not raw_cookies:
                  # Fallback
                  raw_cookies = [resp.headers['Set-Cookie']]
        else:
             raw_cookies = []

        from core.validator import Validator
        validator = Validator()

        for cookie_str in raw_cookies:
            # Basic parsing
            parts = cookie_str.split(";")
            if not parts:
                continue
                
            cookie_pair = parts[0].strip()
            if "=" not in cookie_pair:
                continue
                
            cookie_name = cookie_pair.split("=")[0].strip()
            
            # Is this a session cookie?
            if not validator.validate_cookie_is_session(cookie_name):
                 continue

            cookie_lower = cookie_str.lower()
            
            if "httponly" not in cookie_lower:
                self.db.add(
                    title=f"Session Cookie Missing HttpOnly Flag ({cookie_name})",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=f"Session cookie '{cookie_name}' lacks HttpOnly flag — accessible to JavaScript (XSS theft).",
                    remediation="Set HttpOnly flag on all session cookies.",
                    cvss="5.4", 
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["is_session_cookie", "httponly_missing"]
                )
                self.ui.find("high", f"Cookie missing HttpOnly: {cookie_name}", self.base_url)
                
            if "secure" not in cookie_lower and self.base_url.startswith("https"):
                self.db.add(
                    title=f"Session Cookie Missing Secure Flag ({cookie_name})",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=f"Session cookie '{cookie_name}' lacks Secure flag — transmitted over HTTP.",
                    remediation="Set Secure flag on all session cookies.",
                    cvss="5.4", 
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["is_session_cookie", "secure_missing"]
                )

        # ── AI: assess combined header risk ──────────────────────────────
        if self.ai and self.ai.enabled:
            missing_names = [
                h for h in self.REQUIRED_HEADERS
                if h.lower() not in headers
            ]
            if missing_names:
                ai_note = self.ai.analyze_headers(
                    self.base_url,
                    dict(resp.headers),
                    missing_names,
                )
                if ai_note:
                    self.ui.subsection("AI Header Risk Assessment")
                    for line in ai_note.split("\n"):
                        self.ui.raw(f"    {line}")
                    self.ui.blank()

        self.ui.ok("Headers analysis complete")


# ─── JS Analysis Module ───────────────────────────────────────────────────────