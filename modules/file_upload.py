"""
FileUploadModule — GhostRecon module.
Analyzes file upload endpoints for missing validation.
"""
import time

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class FileUploadModule(BaseModule):
    NAME = "File Upload"

    def run(self):
        self.ui.section("File Upload Security Analysis")
        if not requests:
            return

        forms = self.ctx.get("forms", [])
        upload_endpoints = []
        
        for form in forms:
            inputs = form.get("inputs", [])
            for inp in inputs:
                if inp.get("type", "").lower() == "file":
                    upload_endpoints.append(form.get("url", self.base_url))
                    break
                    
        if not upload_endpoints:
             self.ui.info("No file upload forms discovered.")
             return
             
        s = self._session()
        found = 0
        
        for url in set(upload_endpoints):
            # We will attempt a benign test upload to see how it's handled
            # A tiny SVG file that is technically an image, but can contain scripts
            svg_content = b'<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"><text x="10" y="20" font-size="20">test</text></svg>'
            
            files = {'file': ('ghostrecon_test.svg', svg_content, 'image/svg+xml')}
            
            try:
                # Try to upload
                resp = s.post(url, files=files, timeout=self.timeout)
                
                # Check if it was accepted (200 OK or 201 Created)
                if resp.status_code in [200, 201] and "ghostrecon_test.svg" in resp.text:
                    self.db.add(
                        title="Unrestricted File Upload Potential (SVG)",
                        severity="medium", url=url, module=self.NAME,
                        description=(
                            "The file upload endpoint accepted an SVG file. "
                            "SVGs can contain embedded JavaScript (Stored XSS). "
                            "Ensure SVGs are sanitized or served with a Content-Security-Policy."
                        ),
                        remediation="Validate file contents, not just extensions. Serve uploaded files from a separate domain. Force download or sanitize SVGs.",
                        cvss="5.4",
                        confidence="MEDIUM",
                        confidence_score=60,
                        validation_steps=["file_upload_accepted"]
                    )
                    self.ui.find("medium", "SVG File Upload Accepted", url)
                    found += 1
            except Exception:
                pass

        if found == 0:
            self.ui.info("No file upload vulnerabilities detected.")
