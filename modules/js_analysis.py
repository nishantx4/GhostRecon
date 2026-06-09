"""
JSModule — GhostRecon module.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


class JSModule(BaseModule):
    NAME = "JS Analysis"

    SECRET_PATTERNS = [
        (r'api[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key"),
        (r'secret[_-]?key\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key"),
        (r'aws_access_key_id\s*[=:]\s*["\']?(AKIA[A-Z0-9]{16})["\']?', "AWS Access Key"),
        (r'(AKIA[A-Z0-9]{16})', "AWS Access Key"),
        (r'password\s*[=:]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
        (r'token\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Token"),
        (r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "JWT Token"),
        (r'mongodb\+srv://[^\s"\'<>]+', "MongoDB Connection String"),
        (r'mysql://[^\s"\'<>]+', "MySQL Connection String"),
        (r'postgres://[^\s"\'<>]+', "PostgreSQL Connection String"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),
        (r'ghp_[A-Za-z0-9]{36}', "GitHub Personal Access Token"),
        (r'sk-[A-Za-z0-9]{32,}', "OpenAI/Anthropic API Key"),
        (r'xox[baprs]-[A-Za-z0-9\-]+', "Slack Token"),
        (r'https?://[^/\s"\']+\.internal[^"\'<>\s]*', "Internal URL"),
        (r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^"\'<>\s]*', "Internal IP URL"),
    ]

    def run(self):
        self.ui.section("JavaScript Analysis — Secret & Endpoint Extraction")
        if not requests:
            return

        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        endpoints = self.ctx.get("endpoints", [self.base_url])
        js_files  = [ep for ep in endpoints if ep.endswith(".js")]

        # Also try common JS file paths
        common_js = ["/static/js/main.js", "/js/app.js", "/assets/app.js",
                     "/static/app.js", "/js/bundle.js", "/dist/main.js"]
        for path in common_js:
            js_files.append(urllib.parse.urljoin(self.base_url, path))

        self.ui.info(f"Analyzing {len(js_files)} JavaScript files...")
        found_secrets = []

        for js_url in js_files[:30]:  # Cap at 30 files
            resp = self._get(js_url)
            if not resp or resp.status_code != 200:
                continue
            content = resp.text
            for pattern, secret_type in self.SECRET_PATTERNS:
                for match in re.finditer(pattern, content, re.I):
                    val = match.group(1) if len(match.groups()) > 0 else match.group(0)
                    # Skip obvious test/placeholder values
                    skip = {"your_key", "your_secret", "example", "placeholder",
                            "changeme", "xxxxxxxx", "aaaa", "1234", "test"}
                    if any(s in val.lower() for s in skip):
                        continue
                    found_secrets.append((js_url, secret_type, val[:40]))

        self.ctx["js_secrets"] = found_secrets
        if found_secrets:
            for url, stype, val in found_secrets:
                self.db.add(
                    title=f"Secret Exposed in JavaScript: {stype}",
                    severity="high",
                    url=url,
                    module=self.NAME,
                    description=f"A {stype} was found hardcoded in client-side JavaScript: {val}...",
                    remediation="Remove all secrets from client-side code. Use server-side environment variables.",
                    cvss="7.5", confidence="medium",
                )
                self.ui.find("high", f"JS Secret: {stype}", url)
        else:
            self.ui.info("No secrets found in JavaScript files.")


# ─── Params Module ─────────────────────────────────────────────────────────────