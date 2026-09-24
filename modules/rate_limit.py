"""
RateLimitModule — GhostRecon module.
Detects missing rate limits on sensitive endpoints.
"""
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class RateLimitModule(BaseModule):
    NAME = "Rate Limit"

    def run(self):
        self.ui.section("Rate Limit / Brute Force Protection Detection")
        if not requests:
            return

        # Find likely authentication or sensitive endpoints
        sensitive_endpoints = []
        for ep in self.ctx.get("endpoints", []):
            if any(x in ep.lower() for x in ["login", "auth", "signin", "reset", "forgot", "otp"]):
                sensitive_endpoints.append(ep)

        if not sensitive_endpoints:
            self.ui.info("No clearly sensitive authentication endpoints found.")
            # We could test base URL, but it's likely just to get WAF blocked, not useful
            return

        s = self._session()
        found = 0

        for endpoint in sensitive_endpoints[:3]:
            # Send 30 rapid requests. Each request is caught individually —
            # previously one flaky/timed-out request anywhere in the loop
            # raised out to the outer `except: pass` and aborted the ENTIRE
            # 30-request test for that endpoint, silently reporting nothing
            # rather than "no rate limit observed" or retrying.
            hit_rate_limit = False
            completed = 0
            for i in range(30):
                try:
                    # Rotate IP to test bypass
                    headers = {"X-Forwarded-For": f"127.0.0.{i+1}"}
                    resp = s.get(endpoint, headers=headers, timeout=5)
                    completed += 1

                    if resp.status_code == 429:
                        hit_rate_limit = True
                        break

                    time.sleep(0.01)  # rapid fire
                except Exception:
                    continue

            if completed >= 20:  # enough real requests landed to trust the result
                if not hit_rate_limit:
                    self.db.add(
                        title="Missing Rate Limiting on Authentication Endpoint",
                        severity="high", url=endpoint, module=self.NAME,
                        description=(
                            "The endpoint accepted 30 rapid sequential requests without returning "
                            "HTTP 429 (Too Many Requests) or blocking the IP. "
                            "This leaves the application vulnerable to brute-force and credential stuffing attacks."
                        ),
                        remediation="Implement strict rate limiting and account lockout policies for authentication endpoints.",
                        cvss="7.5",
                        confidence="HIGH",
                        confidence_score=85,
                        validation_steps=["rapid_requests_accepted", "no_429_returned"]
                    )
                    self.ui.find("high", "Missing Rate Limit", endpoint)
                    found += 1

        if found == 0:
            self.ui.info("No rate limit vulnerabilities detected.")
