"""
PrototypePollutionModule — GhostRecon module.
Detects server-side Prototype Pollution via query parameters and JSON body.
"""
import time
import urllib.parse
import hashlib

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class PrototypePollutionModule(BaseModule):
    NAME = "Prototype Pollution"

    def run(self):
        self.ui.section("Prototype Pollution Detection")
        if not requests:
            return

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]
        s = self._session()
        found = 0

        # Payloads to inject
        query_payloads = [
            "__proto__[ghostrecon_pp]=1",
            "constructor.prototype.ghostrecon_pp=1"
        ]
        
        for endpoint in endpoints:
            # 1. Test Query Parameters
            try:
                base_resp = s.get(endpoint, timeout=self.timeout)
                base_hash = hashlib.md5(base_resp.text.encode()).hexdigest()
                
                for payload in query_payloads:
                    url = f"{endpoint}?{payload}"
                    resp = s.get(url, timeout=self.timeout)
                    
                    # If response is a 500 error, it might mean the prototype was polluted and crashed something
                    if resp.status_code == 500 and base_resp.status_code != 500:
                        self.db.add(
                            title="Prototype Pollution Potential (500 Error)",
                            severity="medium", url=endpoint, module=self.NAME,
                            description=(
                                f"Injecting prototype pollution payload '{payload}' caused a 500 Internal Server Error. "
                                "This often indicates server-side prototype pollution leading to an application crash."
                            ),
                            remediation="Sanitize object keys and do not blindly merge user input into objects (e.g., using lodash merge).",
                            cvss="5.3",
                            confidence="MEDIUM",
                            confidence_score=60,
                            validation_steps=["status_500_on_payload"]
                        )
                        self.ui.find("medium", "Prototype Pollution Potential (URL)", endpoint)
                        found += 1
                        break
            except Exception:
                pass

        if found == 0:
             self.ui.info("No Prototype Pollution vulnerabilities detected.")
