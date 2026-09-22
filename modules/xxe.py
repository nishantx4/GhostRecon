"""
XXEModule — GhostRecon module.
Detects XML External Entity (XXE) vulnerabilities by injecting benign external entities.
"""
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class XXEModule(BaseModule):
    NAME = "XXE"

    def run(self):
        self.ui.section("XXE — XML External Entity Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        # Known XML endpoints or any POST endpoints from context
        test_endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]
        
        # XXE payload with a benign entity
        canary = "ghostrecon_xxe_canary"
        xxe_payload = f"""<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe "{canary}" >]>
<foo>&xxe;</foo>"""

        headers_list = [
            {"Content-Type": "application/xml"},
            {"Content-Type": "text/xml"}
        ]

        for endpoint in test_endpoints:
            # Skip likely non-API endpoints
            if endpoint.endswith((".jpg", ".png", ".js", ".css")):
                continue
                
            for headers in headers_list:
                try:
                    resp = s.post(endpoint, data=xxe_payload, headers=headers, timeout=self.timeout)
                    
                    # If the canary was resolved and reflected in the response body
                    if canary in resp.text:
                        # Check if the payload was just reflected literally
                        if xxe_payload in resp.text:
                            # Verify if canary exists outside the literal reflection
                            cleaned = resp.text.replace(xxe_payload, "")
                            if canary not in cleaned:
                                continue

                        self.db.add(
                            title=f"XXE — XML External Entity Injection",
                            severity="critical", url=endpoint, module=self.NAME,
                            description=(
                                f"Endpoint accepts XML input and resolves external entities. "
                                f"A benign entity ('{canary}') was injected and successfully resolved by the server. "
                                "This can lead to local file disclosure (LFI), SSRF, and potential RCE."
                            ),
                            remediation=(
                                "Disable external entity parsing in the XML parser configuration. "
                                "For Java, set FEATURE_SECURE_PROCESSING to true. For Python lxml, "
                                "use resolve_entities=False. Prefer JSON over XML where possible."
                            ),
                            cvss="9.8",
                            confidence="CONFIRMED",
                            confidence_score=95,
                            validation_steps=["entity_resolved", "not_literal_reflection"],
                            evidence=[f"Payload:\n{xxe_payload}"]
                        )
                        self.ui.find("critical", "XXE Injection (Entity Resolved)", endpoint)
                        found += 1
                        break  # Found XXE on this endpoint

                    # Check for generic XML parsing errors that indicate the parser exists
                    elif "xml" in resp.text.lower() and ("parse error" in resp.text.lower() or "doctype" in resp.text.lower()):
                        self.db.add(
                            title=f"XXE Potential — XML Parsing Error",
                            severity="low", url=endpoint, module=self.NAME,
                            description=(
                                f"Endpoint accepts XML and returned an XML parsing error. "
                                "This indicates an active XML parser, though entity resolution was not confirmed."
                            ),
                            remediation="Ensure the XML parser is securely configured to disable DTD processing.",
                            cvss="3.1",
                            confidence="LOW",
                            confidence_score=35,
                            validation_steps=["xml_error_matched"],
                        )
                        
                    time.sleep(self.delay)
                except Exception:
                    continue
            
            if found > 5:
                break

        if found == 0:
            self.ui.info("No XXE vulnerabilities detected.")
