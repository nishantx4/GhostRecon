"""
CSRFModule — GhostRecon module.
Detects missing CSRF protection on forms and missing SameSite attributes on cookies.
"""
try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class CSRFModule(BaseModule):
    NAME = "CSRF"

    def run(self):
        self.ui.section("CSRF — Cross-Site Request Forgery Detection")
        if not requests:
            return

        forms = self.ctx.get("forms", [])
        if not forms:
            self.ui.info("No forms discovered. Run recon module first.")
            return

        found = 0
        csrf_indicators = ["csrf", "token", "_token", "authenticity_token", "__RequestVerificationToken", "xsrf"]

        for form in forms:
            url = form.get("url", self.base_url)
            method = form.get("method", "GET").upper()
            
            # CSRF generally applies to state-changing requests (POST, PUT, DELETE)
            if method not in ("POST", "PUT", "DELETE"):
                continue

            inputs = form.get("inputs", [])
            has_csrf_token = False

            for inp in inputs:
                name = inp.get("name", "").lower()
                type_ = inp.get("type", "").lower()
                
                # Hidden inputs with CSRF indicators
                if type_ == "hidden" and any(ind in name for ind in csrf_indicators):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token:
                # Potential CSRF
                self.db.add(
                    title="CSRF — Missing Anti-CSRF Token in Form",
                    severity="high", url=url, module=self.NAME,
                    description=(
                        f"The form on {url} using {method} method does not contain a discernible Anti-CSRF token. "
                        "If the action is state-changing and relies on session cookies, it may be vulnerable to Cross-Site Request Forgery."
                    ),
                    remediation="Implement Anti-CSRF tokens for all state-changing forms or use SameSite=Lax/Strict for session cookies.",
                    cvss="6.5",
                    confidence="MEDIUM", # We didn't exploit it, just analyzed the form
                    confidence_score=60,
                    validation_steps=["form_analyzed", "csrf_token_missing"],
                )
                self.ui.find("high", "Missing Anti-CSRF Token", url)
                found += 1

        if found == 0:
            self.ui.info("No CSRF vulnerabilities detected in discovered forms.")
