"""
BrokenAuthModule — GhostRecon module.
Checks for session management flaws and authentication weaknesses.
"""
try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class BrokenAuthModule(BaseModule):
    NAME = "Broken Auth"

    def run(self):
        self.ui.section("Broken Authentication — Session Security")
        if not requests:
            return

        s = self._session()
        found = 0

        # Session indicators
        session_names = ["session", "sess", "sid", "token", "auth", "jwt", "phpsessid", "jsessionid", "connect.sid"]
        tracking_names = ["_ga", "_gid", "_fbp", "__utm", "_hj"]

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:10]
        seen_cookie_names = set()  # avoid re-flagging the same cookie at every endpoint

        for endpoint in endpoints:
            try:
                resp = s.get(endpoint, timeout=self.timeout)

                # Only inspect cookies THIS response actually set. `s.cookies`
                # is the session-wide jar — it keeps accumulating every cookie
                # ever seen, so checking it on every iteration re-flags the
                # same cookie (set once on the first request) at every
                # subsequent endpoint's URL, producing near-duplicate findings.
                for cookie in resp.cookies:
                    name_lower = cookie.name.lower()

                    # Skip known tracking cookies
                    if any(name_lower.startswith(t) for t in tracking_names):
                        continue

                    # Check if it looks like a session cookie
                    if any(s_name in name_lower for s_name in session_names):
                        if cookie.name in seen_cookie_names:
                            continue
                        seen_cookie_names.add(cookie.name)

                        issues = []

                        if not cookie.has_nonstandard_attr('HttpOnly'):
                            issues.append("Missing HttpOnly")

                        if not cookie.secure and endpoint.startswith('https'):
                            issues.append("Missing Secure")

                        samesite = cookie.get_nonstandard_attr('SameSite')
                        if not samesite:
                            issues.append("Missing SameSite")

                        if issues:
                            # Redact the actual token value — it's a live
                            # credential and shouldn't be persisted verbatim
                            # into JSON/Markdown report output.
                            value = cookie.value or ""
                            redacted = (value[:4] + "…" + value[-4:]) if len(value) > 10 else "(short value)"
                            self.db.add(
                                title=f"Broken Auth — Insecure Session Cookie ({cookie.name})",
                                severity="high", url=endpoint, module=self.NAME,
                                description=(
                                    f"The session cookie '{cookie.name}' has security flaws: {', '.join(issues)}. "
                                    "This increases the risk of XSS-based theft and CSRF."
                                ),
                                remediation="Set HttpOnly, Secure, and SameSite=Lax (or Strict) attributes on all session cookies.",
                                cvss="5.3",
                                confidence="HIGH",
                                confidence_score=85,
                                validation_steps=["cookie_analyzed", "flags_missing"],
                                evidence=[f"Cookie: {cookie.name}={redacted}", f"Missing: {', '.join(issues)}"]
                            )
                            self.ui.find("high", f"Insecure Session Cookie: {cookie.name}", endpoint)
                            found += 1
            except Exception:
                pass

        if found == 0:
            self.ui.info("No session security issues detected.")
