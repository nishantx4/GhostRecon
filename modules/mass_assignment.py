"""
MassAssignmentModule — GhostRecon module.
Detects potential Mass Assignment vulnerabilities by injecting extra JSON fields.
"""
import json
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class MassAssignmentModule(BaseModule):
    NAME = "Mass Assignment"

    def run(self):
        self.ui.section("Mass Assignment Detection")
        if not requests:
            return
        
        # We only check JSON endpoints that accept POST
        # For simplicity, we just look for API endpoints
        endpoints = [ep for ep in self.ctx.get("endpoints", []) if "api" in ep.lower() or "users" in ep.lower()]
        
        if not endpoints:
             self.ui.info("No suitable API endpoints found for Mass Assignment testing.")
             return

        s = self._session()
        found = 0
        
        # We'll try to add this extra field to JSON POST requests
        extra_fields = {"isAdmin": True, "role": "admin", "ghostrecon_test": True}

        for ep in endpoints[:10]:
            try:
                # Basic GET to see if it responds to JSON
                headers = {"Content-Type": "application/json"}
                # Try a POST with the extra fields
                resp = s.post(ep, json=extra_fields, headers=headers, timeout=self.timeout)
                
                # If it responds 200/201 and reflects our test field, it might be vulnerable
                if resp.status_code in [200, 201] and "ghostrecon_test" in resp.text:
                     self.db.add(
                        title="Mass Assignment Potential",
                        severity="medium", url=ep, module=self.NAME,
                        description=(
                            "The endpoint accepted and processed a JSON payload containing unexpected "
                            "fields (e.g., 'ghostrecon_test'). This suggests the application might "
                            "blindly bind input to internal objects, which is a Mass Assignment vulnerability."
                        ),
                        remediation="Use explicit binding or DTOs. Never blindly bind JSON input to internal model objects.",
                        cvss="5.3",
                        confidence="MEDIUM",
                        confidence_score=60,
                        validation_steps=["extra_field_reflected"]
                    )
                     self.ui.find("medium", "Mass Assignment Potential", ep)
                     found += 1
                time.sleep(self.delay)
            except Exception:
                pass

        if found == 0:
             self.ui.info("No Mass Assignment vulnerabilities detected.")
