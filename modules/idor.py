"""
IDORModule — GhostRecon module.
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


class IDORModule(BaseModule):
    NAME = "IDOR Detector"

    def run(self):
        self.ui.section("IDOR — Insecure Direct Object Reference Detection")
        endpoints = self.ctx.get("endpoints", [])
        idor_candidates = []

        # Find endpoints with numeric IDs
        id_pattern = re.compile(r'(/[^?#]*/)(\d+)(/|$|\?)')
        uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')

        for ep in endpoints:
            if id_pattern.search(ep):
                idor_candidates.append(("numeric_id", ep))
            if uuid_pattern.search(ep):
                idor_candidates.append(("uuid", ep))

        # Also check API patterns
        api_patterns = ["/api/v1/user/", "/api/v1/users/", "/api/v1/document/",
                        "/api/v1/account/", "/api/v1/profile/", "/api/user/",
                        "/user/", "/profile/", "/account/", "/document/", "/file/"]
        for pattern in api_patterns:
            for test_id in ["1", "2", "100"]:
                url = f"{self.base_url}{pattern}{test_id}"
                idor_candidates.append(("api_probe", url))

        if not idor_candidates:
            self.ui.info("No IDOR candidates found in current endpoint list.")
            self.ui.info("Tip: Run recon first or provide URLs with numeric IDs.")
            return

        self.ui.info(f"Testing {len(idor_candidates)} IDOR candidate(s)...")
        s = self._session()
        found = 0

        for id_type, url in idor_candidates[:30]:
            try:
                resp = s.get(url, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.text) > 50:
                    # ── AI-enhanced check: let AI decide if response leaks private data
                    ai_verdict = None
                    if self.ai and self.ai.enabled:
                        ai_verdict = self.ai.analyze_idor_response(
                            url, resp.text, url.split('/')[-1]
                        )

                    # Fallback: keyword-based check
                    data_indicators = ["email", "username", "user_id", "account",
                                       "password", "phone", "address", "token"]
                    resp_lower = resp.text.lower()
                    keyword_hit = any(ind in resp_lower for ind in data_indicators)

                    is_idor = False
                    confidence = "medium"
                    reason = "Response contains user data keywords"

                    if ai_verdict:
                        is_idor    = ai_verdict.get("is_idor", False)
                        confidence = ai_verdict.get("confidence", "medium")
                        reason     = ai_verdict.get("reason", reason)
                    elif keyword_hit:
                        is_idor = True

                    if is_idor:
                        self.db.add(
                            title="Potential IDOR — Object Access Without Auth Check",
                            severity="high", url=url, module=self.NAME,
                            description=(
                                f"Endpoint {url} returned 200 OK with likely user data. "
                                f"AI assessment: {reason}. "
                                "Verify with two accounts: if Account B can read Account A's "
                                "data by changing the ID, this is confirmed IDOR."
                            ),
                            remediation=(
                                "Implement server-side authorization. Verify requesting user "
                                "owns the object. Use non-sequential UUIDs."
                            ),
                            cvss="8.1", confidence=confidence,
                        )
                        self.ui.find("high", f"Potential IDOR — {reason}", url)
                        found += 1
                time.sleep(self.delay)
            except Exception:
                continue

        if found == 0:
            self.ui.info("No IDOR candidates confirmed — manual testing with 2 accounts recommended.")
        else:
            self.ui.ok(f"IDOR scan complete — {found} potential finding(s) (requires manual confirmation)")


# ─── GraphQL Module ────────────────────────────────────────────────────────────