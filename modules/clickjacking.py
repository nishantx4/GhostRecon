"""
ClickjackingModule — GhostRecon module.
Detects missing frame protection headers (X-Frame-Options, CSP frame-ancestors).
"""
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class ClickjackingModule(BaseModule):
    NAME = "Clickjacking"

    def run(self):
        self.ui.section("Clickjacking — Frame Protection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()

        try:
            resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            self.ui.error("Failed to connect to target.")
            return

        xfo = resp.headers.get("X-Frame-Options", "").strip().upper()
        csp = resp.headers.get("Content-Security-Policy", "")

        has_xfo = xfo in ("DENY", "SAMEORIGIN")
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if has_xfo and has_frame_ancestors:
            self.ui.info("Frame protection is properly configured (X-Frame-Options + CSP frame-ancestors).")
            return

        if not has_xfo and not has_frame_ancestors:
            self.db.add(
                title="Clickjacking — No Frame Protection",
                severity="medium", url=self.base_url, module=self.NAME,
                description=(
                    "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors "
                    "headers are set. The page can be embedded in an iframe on any domain, "
                    "enabling clickjacking/UI redressing attacks."
                ),
                remediation=(
                    "Set X-Frame-Options: DENY or SAMEORIGIN on all responses. "
                    "Additionally, set Content-Security-Policy: frame-ancestors 'self'."
                ),
                cvss="4.7",
                confidence="HIGH",
                confidence_score=85,
                validation_steps=["xfo_missing", "csp_frame_ancestors_missing"],
            )
            self.ui.find("medium", "Clickjacking — Both protections missing", self.base_url)
        elif not has_xfo:
            self.db.add(
                title="Clickjacking — Missing X-Frame-Options (CSP present)",
                severity="low", url=self.base_url, module=self.NAME,
                description=(
                    "X-Frame-Options header is not set, but CSP frame-ancestors is present. "
                    "Older browsers that don't support CSP may still be vulnerable."
                ),
                remediation="Add X-Frame-Options: DENY or SAMEORIGIN for defense-in-depth.",
                cvss="3.1",
                confidence="MEDIUM",
                confidence_score=60,
                validation_steps=["xfo_missing", "csp_present"],
            )
            self.ui.find("low", "Missing X-Frame-Options (CSP fallback exists)", self.base_url)
        else:
            self.db.add(
                title="Clickjacking — Missing CSP frame-ancestors (XFO present)",
                severity="info", url=self.base_url, module=self.NAME,
                description=(
                    "Content-Security-Policy frame-ancestors is not set, but X-Frame-Options is present. "
                    "Consider adding CSP frame-ancestors for modern browser support."
                ),
                remediation="Add Content-Security-Policy: frame-ancestors 'self' for defense-in-depth.",
                cvss="0.0",
                confidence="MEDIUM",
                confidence_score=60,
                validation_steps=["xfo_present", "csp_missing"],
            )
            self.ui.find("info", "Missing CSP frame-ancestors (XFO fallback exists)", self.base_url)
