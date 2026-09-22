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
                    
                    # FP Check: If the page is just the default homepage/soft-404, skip
                    baseline = self.ctx.get('baseline_profile')
                    if baseline and baseline.matches_soft_404(resp.text, resp.status_code):
                        continue

                    # Fallback: strict keyword-based check (require multiple to avoid FP like "email us" in footer)
                    data_indicators = ["email", "username", "user_id", "account_id", 
                                       "password_hash", "phone_number", "billing_address", "auth_token"]
                    
                    # Ignore common public site words
                    ignore_patterns = ["contact email", "email address", "enter your email", "email us at"]
                    resp_lower = resp.text.lower()
                    
                    for ignore in ignore_patterns:
                        resp_lower = resp_lower.replace(ignore, "")
                        
                    keyword_matches = sum(1 for ind in data_indicators if ind in resp_lower)
                    
                    is_idor = False
                    confidence = "MEDIUM"
                    confidence_score = 60
                    reason = f"Response contains {keyword_matches} user data keywords"

                    # ── Validator AI check if available
                    if self.ai and self.ai.enabled:
                        ai_verdict = self.ai._call(
                            system="You are a security auditor. Assess if this HTTP response indicates an Insecure Direct Object Reference (IDOR) leaking private user data. Return JSON: {\"is_idor\": true/false, \"confidence\": 0.0-1.0, \"reason\": \"text\"}",
                            user=f"URL: {url}\nResponse snippet:\n{resp.text[:1000]}\nDoes this look like private user data leaked via IDOR?",
                            max_tokens=200
                        )
                        if ai_verdict:
                            try:
                                import json
                                start = ai_verdict.find("{")
                                end = ai_verdict.rfind("}") + 1
                                if start != -1 and end > start:
                                    parsed = json.loads(ai_verdict[start:end])
                                    is_idor = parsed.get("is_idor", False)
                                    confidence_score = int(parsed.get("confidence", 0.6) * 100)
                                    confidence = "HIGH" if confidence_score > 80 else "MEDIUM"
                                    reason = parsed.get("reason", reason)
                            except Exception:
                                pass
                    elif keyword_matches >= 2:
                        is_idor = True

                    if is_idor:
                        self.db.add(
                            title="Potential IDOR — Object Access Without Auth Check",
                            severity="high", url=url, module=self.NAME,
                            description=(
                                f"Endpoint {url} returned 200 OK with likely user data. "
                                f"Assessment: {reason}. "
                                "Verify with two accounts: if Account B can read Account A's "
                                "data by changing the ID, this is confirmed IDOR."
                            ),
                            remediation=(
                                "Implement server-side authorization. Verify requesting user "
                                "owns the object. Use non-sequential UUIDs."
                            ),
                            cvss="8.1", 
                            confidence=confidence,
                            confidence_score=confidence_score,
                            validation_steps=["status_200", "keywords_matched_or_ai_verified"]
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