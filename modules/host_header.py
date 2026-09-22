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
            {"X-Host": evil_host}
        ]

        try:
            for headers in headers_to_test:
                # Use a custom session to bypass default Host header enforcement in some requests wrappers
                req = requests.Request('GET', self.base_url, headers=headers)
                prepared = req.prepare()
                
                # Force the Host header (requests sometimes overrides it in prepare)
                if "Host" in headers:
                    prepared.headers["Host"] = evil_host
                    
                resp = s.send(prepared, timeout=self.timeout, allow_redirects=False)

                # Check if it's reflected in the body (e.g., in links)
                if evil_host in resp.text:
                    self.db.add(
                        title="Host Header Injection — Body Reflection",
                        severity="medium", url=self.base_url, module=self.NAME,
                        description=(
                            f"The injected host '{evil_host}' was reflected in the response body. "
                            "This can lead to password reset poisoning or cache poisoning."
                        ),
                        remediation="Do not trust the Host header. Use a securely configured SERVER_NAME or equivalent.",
                        cvss="5.3",
                        confidence="HIGH",
                        confidence_score=85,
                        validation_steps=["host_reflected_in_body"]
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
                            f"The injected host '{evil_host}' caused an open redirect to {location}."
                        ),
                        remediation="Do not trust the Host header for generating redirects.",
                        cvss="6.1",
                        confidence="CONFIRMED",
                        confidence_score=95,
                        validation_steps=["host_in_location_header"]
                    )
                     self.ui.find("high", "Host Header Injection (Redirect)", self.base_url)
                     return

        except Exception:
            pass

        self.ui.info("No Host Header Injection vulnerabilities detected.")
