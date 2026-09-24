"""
FileUploadModule — GhostRecon module.
Analyzes file upload endpoints for missing validation.

NOTE on ctx['forms']: ReconModule._extract_forms stores `inputs` as a plain
{name: value} dict, and deliberately EXCLUDES type="file" inputs from it
entirely (see modules/recon.py). That means file inputs can never be
recovered from crawled form data — this module can't tell which forms are
upload forms from that source at all. We compensate with a name-based
heuristic over whatever inputs *are* present, plus independent probing of
common upload endpoint paths (also covers the very common case of a
JS-driven upload widget with no <form> markup at all).
"""
import re
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


UPLOAD_NAME_HINTS = ("file", "upload", "attach", "avatar", "photo", "image",
                     "document", "resume", "cv", "media", "picture")

COMMON_UPLOAD_PATHS = [
    "/upload", "/api/upload", "/upload.php", "/api/v1/upload", "/api/v2/upload",
    "/file/upload", "/files/upload", "/media/upload", "/api/files",
    "/api/media", "/avatar/upload", "/profile/upload", "/attachments",
]

REJECTION_SIGNALS = ("invalid file", "not allowed", "unsupported file",
                      "file type", "extension not", "rejected", "forbidden")


class FileUploadModule(BaseModule):
    NAME = "File Upload"

    def run(self):
        self.ui.section("File Upload Security Analysis")
        if not requests:
            return

        upload_endpoints = set()

        for form in self.ctx.get("forms", []):
            inputs = form.get("inputs", {})
            names = inputs.keys() if isinstance(inputs, dict) else inputs
            if any(isinstance(n, str) and any(h in n.lower() for h in UPLOAD_NAME_HINTS) for n in names):
                upload_endpoints.add((form.get("action", self.base_url), form.get("method", "POST").upper()))

        for path in COMMON_UPLOAD_PATHS:
            upload_endpoints.add((urllib.parse.urljoin(self.base_url, path), "POST"))

        s = self._session()
        found = 0

        for url, method in upload_endpoints:
            try:
                if self._test_upload(s, url, method):
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No file upload vulnerabilities detected.")

    def _test_upload(self, session, url, method) -> bool:
        marker = "ghostrecon_test"
        svg_content = (
            b'<?xml version="1.0" standalone="no"?>'
            b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
            b'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">'
            b'<text x="10" y="20" font-size="20">test</text></svg>'
        )
        files = {"file": (f"{marker}.svg", svg_content, "image/svg+xml")}

        try:
            resp = session.request(method, url, files=files, timeout=self.timeout)
        except Exception:
            return False

        if resp.status_code not in (200, 201):
            return False

        body_lower = resp.text.lower()
        if any(sig in body_lower for sig in REJECTION_SIGNALS) and marker not in resp.text:
            return False
        if marker not in resp.text and resp.status_code != 201:
            # No echo of our filename and not an explicit "Created" — too
            # weak a signal that anything actually happened server-side.
            return False

        # Try to confirm the file is genuinely stored and retrievable.
        stored_url = self._extract_stored_url(resp, url, marker)
        confirmed = False
        if stored_url:
            try:
                check = session.get(stored_url, timeout=self.timeout)
                if check.status_code == 200 and (marker.encode() in check.content or b"<svg" in check.content):
                    confirmed = True
            except Exception:
                pass

        severity = "high" if confirmed else "medium"
        confidence = "CONFIRMED" if confirmed else "MEDIUM"
        confidence_score = 90 if confirmed else 55

        desc = (
            "The file upload endpoint accepted an SVG file without validating its content. "
            "SVGs can contain embedded JavaScript (Stored XSS) or trigger XXE in vulnerable parsers."
        )
        if confirmed:
            desc += f" The uploaded file was independently confirmed retrievable at: {stored_url}"
        else:
            desc += (
                " The server accepted the upload but a retrievable URL for the stored file could not "
                "be confirmed automatically — verify manually."
            )

        self.db.add(
            title="Unrestricted File Upload" + (" (Confirmed)" if confirmed else " (Potential)"),
            severity=severity, url=stored_url or url, module=self.NAME,
            description=desc,
            remediation="Validate file contents (not just extension/MIME type). Serve uploaded files "
                        "from a separate domain with no script execution, force download for SVG/HTML, "
                        "and sanitize or reject SVG uploads outright.",
            cvss="7.5" if confirmed else "5.4",
            confidence=confidence,
            confidence_score=confidence_score,
            validation_steps=["file_upload_accepted"] + (["stored_file_retrieved"] if confirmed else []),
            evidence=[f"Upload URL: {url}"] + ([f"Stored at: {stored_url}"] if stored_url else []),
        )
        self.ui.find(severity, f"SVG File Upload {'Confirmed' if confirmed else 'Accepted'}", stored_url or url)
        return True

    def _extract_stored_url(self, resp, upload_url, marker):
        try:
            data = resp.json()
            found = self._find_url_in_json(data, marker)
            if found:
                return urllib.parse.urljoin(upload_url, found)
        except Exception:
            pass

        m = re.search(rf'["\'](/[^"\']*{re.escape(marker)}[^"\']*)["\']', resp.text)
        if m:
            return urllib.parse.urljoin(upload_url, m.group(1))
        m = re.search(rf'(https?://[^\s"\']*{re.escape(marker)}[^\s"\']*)', resp.text)
        if m:
            return m.group(1)
        return None

    @classmethod
    def _find_url_in_json(cls, obj, marker):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and (marker in v or (k.lower() in ("url", "path", "file_url", "location", "link") and v)):
                    if v.startswith("/") or v.startswith("http"):
                        return v
                found = cls._find_url_in_json(v, marker)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = cls._find_url_in_json(item, marker)
                if found:
                    return found
        return None
