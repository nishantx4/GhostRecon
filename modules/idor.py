"""
IDORModule — Insecure Direct Object Reference detection.

Instead of flagging a single 200 response, this compares responses across
at least two object IDs at the same endpoint. If different IDs return
distinct, substantial bodies that look like per-object records, the object
is very likely served without an ownership check. An optional session
cookie (ctx['session_cookie']) lets you test as an authenticated user.
"""
import re
import time
import difflib
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


ID_PATTERN   = re.compile(r'(.*/)(\d{1,10})(/?(?:\?.*)?)$')
DATA_INDICATORS = ["email", "username", "user_id", "account", "password",
                   "phone", "address", "token", "ssn", "firstname", "lastname",
                   "order", "invoice", "balance"]


class IDORModule(BaseModule):
    NAME = "IDOR Detector"

    def run(self):
        self.ui.section("IDOR — Insecure Direct Object Reference Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        self.session = self._session()
        cookie = self.ctx.get("session_cookie")
        if cookie:
            self.session.headers.update({"Cookie": cookie})
            self.ui.info("Using provided session cookie for authenticated IDOR testing")

        templates = self._collect_id_templates()
        if not templates:
            self.ui.info("No numeric-ID endpoints found — run recon first or supply ID URLs.")
            return

        self.ui.info(f"Comparing object access across {len(templates)} ID endpoint(s)...")
        found = 0
        for prefix, suffix in templates[:30]:
            if self._test_template(prefix, suffix):
                found += 1
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No IDOR confirmed — manual testing with two accounts still recommended.")
        else:
            self.ui.ok(f"IDOR scan complete — {found} likely finding(s)")

    def _collect_id_templates(self):
        """Return unique (prefix, suffix) pairs where an ID can be swapped in."""
        templates = []
        seen = set()

        for ep in self.ctx.get("endpoints", []):
            m = ID_PATTERN.match(ep)
            if m:
                prefix, _id, suffix = m.group(1), m.group(2), m.group(3)
                key = (prefix, suffix)
                if key not in seen:
                    seen.add(key)
                    templates.append(key)

        # Common API object patterns as fallbacks.
        for pattern in ["/api/v1/users/", "/api/v1/user/", "/api/users/",
                        "/api/v1/document/", "/api/v1/account/", "/api/orders/",
                        "/user/", "/profile/", "/account/", "/document/", "/invoice/"]:
            key = (f"{self.base_url}{pattern}", "")
            if key not in seen:
                seen.add(key)
                templates.append(key)

        return templates

    def _fetch(self, prefix, obj_id, suffix):
        url = f"{prefix}{obj_id}{suffix}"
        try:
            return url, self.session.get(url, timeout=self.timeout)
        except Exception:
            return url, None

    def _test_template(self, prefix, suffix):
        # Fetch two different object IDs and compare.
        url_a, resp_a = self._fetch(prefix, "1", suffix)
        url_b, resp_b = self._fetch(prefix, "2", suffix)

        if not resp_a or not resp_b:
            return False
        if resp_a.status_code != 200 or resp_b.status_code != 200:
            return False

        body_a, body_b = resp_a.text, resp_b.text
        if len(body_a) < 50 or len(body_b) < 50:
            return False

        # Both bodies should look like data records...
        looks_like_data = any(ind in body_a.lower() for ind in DATA_INDICATORS)
        # ...but differ from each other (distinct per-object content).
        ratio = difflib.SequenceMatcher(None, body_a, body_b).quick_ratio()
        distinct = ratio < 0.95 and body_a != body_b

        if not (looks_like_data and distinct):
            return False

        # Optional AI second opinion to cut false positives.
        reason = (f"Two object IDs returned distinct data-like records "
                  f"(similarity {ratio:.2f}) with no apparent ownership check.")
        confidence = "medium"
        if self.ai and self.ai.enabled:
            try:
                verdict = self.ai.analyze_idor_response(url_a, body_a, "1")
                if verdict:
                    if not verdict.get("is_idor", True):
                        return False
                    confidence = verdict.get("confidence", confidence)
                    reason = verdict.get("reason", reason)
            except Exception:
                pass

        self.db.add(
            title="Insecure Direct Object Reference (IDOR)",
            severity="high", url=f"{prefix}{{id}}{suffix}", module=self.NAME,
            description=(
                f"Swapping the object ID at {prefix}<id>{suffix} returns different "
                f"per-object records without an authorization check. {reason} Confirm by "
                "requesting another user's object ID while authenticated as a low-privilege user."
            ),
            remediation=(
                "Enforce server-side authorization: verify the requesting user owns or may "
                "access the object. Prefer non-sequential identifiers (UUIDs) and per-object "
                "access-control checks."
            ),
            cvss="8.1", confidence=confidence,
            evidence=[f"Object 1: {url_a}", f"Object 2: {url_b}",
                      f"Body similarity: {ratio:.2f}"],
            references=["https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control"],
        )
        self.ui.find("high", "IDOR — unprotected object access", f"{prefix}{{id}}{suffix}")
        return True


# --- GraphQL Module ---------------------------------------------------------
