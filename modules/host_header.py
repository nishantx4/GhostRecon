"""
HostHeaderModule — GhostRecon module.
Detects Host Header Injection vulnerabilities.
"""
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class HostHeaderModule(BaseModule):
    NAME = "Host Header Injection"

    def run(self):
        self.ui.section("Host Header Injection Detection")
        if not requests:
            return

        s = self._session()
        evil_host = "ghostrecon-evil-host.example.com"

        headers_to_test = [
            {"Host": evil_host},
            {"X-Forwarded-Host": evil_host},
            {"X-Host": evil_host},
        ]

        for headers in headers_to_test:
            try:
                # Use a custom session to bypass default Host header enforcement in some requests wrappers
                req = requests.Request('GET', self.base_url, headers=headers)
                prepared = req.prepare()

                # Force the Host header (requests sometimes overrides it in prepare)
                if "Host" in headers:
                    prepared.headers["Host"] = evil_host

                resp = s.send(prepared, timeout=self.timeout, allow_redirects=False)
            except Exception:
                continue  # This variant failed — try the next header, don't abort entirely

            header_used = next(iter(headers))

            # Check if it's reflected in the body (e.g., in links)
            if evil_host in resp.text:
                cache_poisoned = self._check_cache_poisoning(s, evil_host)
                if cache_poisoned:
                    self.db.add(
                        title="Host Header Injection — Confirmed Cache Poisoning",
                        severity="critical", url=self.base_url, module=self.NAME,
                        description=(
                            f"Injecting '{header_used}: {evil_host}' was reflected in the response "
                            f"body, AND a follow-up request sent WITHOUT the injected header still "
                            f"returned the poisoned value — the response was cached and is now being "
                            f"served to other visitors. This is live, exploitable web cache poisoning."
                        ),
                        remediation="Do not trust the Host header. Use a securely configured SERVER_NAME or equivalent. Ensure the cache key includes Host/X-Forwarded-Host or strips them from cached responses.",
                        cvss="8.6",
                        confidence="CONFIRMED",
                        confidence_score=98,
                        validation_steps=["host_reflected_in_body", "clean_followup_still_poisoned"],
                        evidence=[f"Header: {header_used}: {evil_host}"],
                    )
                    self.ui.find("critical", "Host Header Injection — Cache Poisoning", self.base_url)
                else:
                    self.db.add(
                        title="Host Header Injection — Body Reflection",
                        severity="medium", url=self.base_url, module=self.NAME,
                        description=(
                            f"The injected host ('{header_used}: {evil_host}') was reflected in the "
                            f"response body. This can lead to password reset poisoning or cache "
                            f"poisoning if any layer in front of the app caches responses."
                        ),
                        remediation="Do not trust the Host header. Use a securely configured SERVER_NAME or equivalent.",
                        cvss="5.3",
                        confidence="HIGH",
                        confidence_score=85,
                        validation_steps=["host_reflected_in_body"],
                    )
                    self.ui.find("medium", "Host Header Injection (Body)", self.base_url)
                return

            # Check if it caused an open redirect
            location = resp.headers.get("Location", "")
            if evil_host in location:
                self.db.add(
                    title="Host Header Injection — Open Redirect",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=(
                        f"Injecting '{header_used}: {evil_host}' caused an open redirect to {location}."
                    ),
                    remediation="Do not trust the Host header for generating redirects.",
                    cvss="6.1",
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["host_in_location_header"],
                )
                self.ui.find("high", "Host Header Injection (Redirect)", self.base_url)
                return

            time.sleep(self.delay)

        self.ui.info("No Host Header Injection vulnerabilities detected.")

    def _check_cache_poisoning(self, s, evil_host):
        """
        After a reflected-Host response, send ONE clean request (no injected
        header) and see if the poisoned value is still being served — that's
        the difference between "the app reflects this header" (medium, needs
        a cache in front of it to matter) and "I just poisoned a live cache
        entry" (critical, immediately exploitable against every visitor).
        """
        try:
            resp = s.get(self.base_url, timeout=self.timeout, allow_redirects=False)
            return evil_host in resp.text
        except Exception:
            return False
