"""
CSRFModule — GhostRecon module.
Detects missing CSRF protection on state-changing HTML forms.

Note: cookie SameSite/HttpOnly/Secure attributes are checked by
modules/broken_auth.py, not here — duplicating that here would just
produce two findings for the same underlying cookie flaw.
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

        # Classic CSRF relies on the browser auto-attaching an ambient
        # credential (a cookie) to a cross-site request. If the only auth
        # signal this target uses is a custom header (e.g. an API token from
        # an OpenAPI spec) and no session cookie was ever supplied/observed,
        # a cross-site page cannot forge that header at all — flagging
        # "missing CSRF token" there would be a structural false positive.
        token_auth_only = bool(self.ctx.get("auth_headers")) and not self.ctx.get("session_cookie")
        if token_auth_only:
            self.ui.info(
                "Target uses header-based auth with no session cookie observed — "
                "CSRF doesn't apply to cross-site requests here (a browser can't forge "
                "the auth header), skipping form-based CSRF checks."
            )
            return

        found = 0
        csrf_indicators = ["csrf", "token", "_token", "authenticity_token", "requestverificationtoken", "xsrf", "nonce"]

        for form in forms:
            # recon.py stores the form's action URL under "action", not "url",
            # and "inputs" as a {name: value} dict, not a list of {name, type}
            # dicts — iterating it as the latter throws AttributeError on the
            # first field and crashes the whole module before it flags anything.
            url = form.get("action", self.base_url)
            method = form.get("method", "GET").upper()

            # CSRF generally applies to state-changing requests (POST, PUT, DELETE)
            if method not in ("POST", "PUT", "DELETE"):
                continue

            inputs = form.get("inputs", {})
            input_names = inputs.keys() if isinstance(inputs, dict) else inputs
            has_csrf_token = any(
                any(ind in str(name).lower() for ind in csrf_indicators)
                for name in input_names
            )

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
                    evidence=[f"Fields on form: {', '.join(input_names) or '(none)'}"],
                )
                self.ui.find("high", "Missing Anti-CSRF Token", url)
                found += 1

        if found == 0:
            self.ui.info("No CSRF vulnerabilities detected in discovered forms.")
