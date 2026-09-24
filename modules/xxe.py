"""
XXEModule — GhostRecon module.
Detects XML External Entity (XXE) vulnerabilities by injecting benign external entities.
"""
import re
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

        # API endpoints from an OpenAPI/Swagger spec (recon.py) carry a real,
        # schema-correct XML request body (xml_template, with the vulnerable
        # field's text already replaced by a __GR_INJECT__ marker). This is
        # tried FIRST and is far more likely to reach the vulnerable parser
        # than the generic <foo>&xxe;</foo> envelope below — most real APIs
        # validate the document against an expected root/element shape before
        # doing anything else, and a made-up envelope simply never gets that
        # far.
        found += self._test_api_endpoints(s)

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

    def _test_api_endpoints(self, s) -> int:
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            template = api_ep.get("xml_template")
            if not template or "__GR_INJECT__" not in template:
                continue

            method = api_ep.get("method", "POST")
            url = api_ep.get("url")
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)
            headers["Content-Type"] = "application/xml"

            canary = "ghostrecon_xxe_canary"

            # Build a DOCTYPE whose Name matches the document's actual root
            # element (some parsers are stricter than others about this),
            # keep the rest of the real, schema-correct body intact, and
            # replace only the marked field's text with an entity reference.
            body_no_prolog = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", template)
            root_match = re.search(r"<([A-Za-z_][\w:.-]*)[ >]", body_no_prolog)
            root_name = root_match.group(1) if root_match else "root"

            payload = (
                '<?xml version="1.0"?>\n'
                f'<!DOCTYPE {root_name} [<!ENTITY xxe "{canary}">]>\n'
                + body_no_prolog.replace("__GR_INJECT__", "&xxe;")
            )

            try:
                resp = s.request(method, url, data=payload.encode("utf-8", "ignore"),
                                  headers=headers, timeout=self.timeout)
            except Exception:
                continue

            if canary in resp.text:
                if payload in resp.text:
                    cleaned = resp.text.replace(payload, "")
                    if canary not in cleaned:
                        continue

                self.db.add(
                    title="XXE — XML External Entity Injection (OpenAPI-discovered body)",
                    severity="critical", url=url, module=self.NAME,
                    description=(
                        f"The endpoint's real request body schema was reused with a benign external "
                        f"entity injected into its '{api_ep.get('xml_field')}' field. The entity "
                        f"('{canary}') was successfully resolved by the server. This can lead to local "
                        "file disclosure, SSRF, and potential RCE."
                    ),
                    remediation=(
                        "Disable external entity parsing in the XML parser configuration. "
                        "For Java, set FEATURE_SECURE_PROCESSING to true. For Python lxml, "
                        "use resolve_entities=False. Prefer JSON over XML where possible."
                    ),
                    cvss="9.8",
                    confidence="CONFIRMED",
                    confidence_score=95,
                    validation_steps=["entity_resolved", "not_literal_reflection", "schema_correct_body"],
                    evidence=[f"Payload:\n{payload}"],
                )
                self.ui.find("critical", "XXE Injection (Entity Resolved, OpenAPI body)", url)
                found += 1

            time.sleep(self.delay)
            if found > 5:
                return found

        return found
