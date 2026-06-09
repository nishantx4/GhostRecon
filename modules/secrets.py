"""
SecretsModule — GhostRecon module.
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


class SecretsModule(BaseModule):
    NAME = "Secrets"

    def run(self):
        self.ui.section("Exposed Secrets — File & Path Probing")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        sensitive_paths = [
            ("/.env",                  "Environment Variables"),
            ("/.env.local",            "Local Environment Variables"),
            ("/.env.production",       "Production Environment Variables"),
            ("/.env.backup",           "Environment Backup"),
            ("/config/database.yml",   "Database Config"),
            ("/config/secrets.yml",    "Secrets Config"),
            ("/wp-config.php",         "WordPress Config"),
            ("/config.php",            "PHP Config"),
            ("/settings.py",           "Django Settings"),
            ("/app/config/parameters.yml", "Symfony Config"),
            ("/database.yml",          "Database Config"),
            ("/.htpasswd",             "Password File"),
            ("/id_rsa",                "Private SSH Key"),
            ("/.ssh/id_rsa",           "Private SSH Key"),
            ("/credentials",           "Credentials File"),
            ("/secrets.json",          "Secrets JSON"),
            ("/config.json",           "Config JSON"),
            ("/application.properties","Spring Boot Config"),
        ]

        s = self._session()
        for path, label in sensitive_paths:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 5:
                    self.db.add(
                        title=f"Sensitive File Exposed: {label} ({path})",
                        severity="critical", url=url, module=self.NAME,
                        description=f"Sensitive file '{path}' ({label}) is accessible without authentication.",
                        remediation=f"Remove '{path}' from the web root or restrict access via server config.",
                        cvss="9.8", confidence="high",
                    )
                    self.ui.find("critical", f"Exposed: {label}", url)
                time.sleep(self.delay)
            except Exception:
                continue


# ─── Reporter Module ───────────────────────────────────────────────────────────