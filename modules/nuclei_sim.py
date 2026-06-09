"""
NucleiModule — GhostRecon module.
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


class NucleiModule(BaseModule):
    NAME = "Nuclei"

    CHECKS = [
        # (path, title, severity, cvss, desc)
        ("/.env",              "Exposed .env File",           "critical", "9.8",
         "Environment file exposed — may contain DB credentials, API keys, secrets."),
        ("/backup.zip",        "Backup Archive Exposed",       "high",    "7.5",
         "Backup archive accessible without authentication."),
        ("/backup.tar.gz",     "Backup Archive Exposed",       "high",    "7.5",
         "Backup archive accessible without authentication."),
        ("/config.php.bak",    "Config Backup Exposed",        "high",    "7.5",
         "PHP config backup file accessible."),
        ("/.git/HEAD",         "Git Repository Exposed",       "high",    "7.5",
         "Git repository metadata exposed — source code may be recoverable."),
        ("/.git/config",       "Git Config Exposed",           "medium",  "6.5",
         "Git config file exposed — may reveal remote URLs and credentials."),
        ("/phpinfo.php",       "PHPInfo Exposed",              "medium",  "5.3",
         "phpinfo() discloses server configuration, paths, and PHP settings."),
        ("/server-status",     "Apache Server Status Exposed", "medium",  "5.3",
         "Apache server-status page leaks request details."),
        ("/wp-config.php.bak", "WordPress Config Backup",      "critical","9.8",
         "WordPress config backup may expose DB credentials."),
        ("/adminer.php",       "Adminer DB Manager Exposed",   "critical","9.8",
         "Adminer database manager accessible — direct DB access possible."),
        ("/phpmyadmin/",       "phpMyAdmin Exposed",           "high",    "8.0",
         "phpMyAdmin accessible — database administration interface exposed."),
        ("/graphql",           "GraphQL Endpoint Found",       "info",    "3.0",
         "GraphQL endpoint detected — test for introspection and batching attacks."),
        ("/api/v1/",           "API Endpoint Found",           "info",    "2.0",
         "API v1 endpoint found — enumerate further."),
        ("/swagger-ui.html",   "Swagger API Docs Exposed",     "medium",  "5.0",
         "Swagger UI exposed — reveals full API specification."),
        ("/api-docs",          "API Documentation Exposed",    "medium",  "5.0",
         "API documentation exposed publicly."),
        ("/.DS_Store",         ".DS_Store File Exposed",       "low",     "4.0",
         ".DS_Store file reveals directory structure on macOS servers."),
        ("/robots.txt",        "Robots.txt Found",             "info",    "0.0",
         "Robots.txt may reveal hidden paths and directories."),
    ]

    def run(self):
        self.ui.section("Nuclei — Common Vulnerability Checks")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        for path, title, severity, cvss, desc in self.CHECKS:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (200, 206):
                    # Extra validation: check for meaningful content
                    if path == "/.env" and "APP_" not in resp.text and "DB_" not in resp.text and len(resp.text) < 10:
                        continue
                    added = self.db.add(
                        title=title, severity=severity, url=url, module=self.NAME,
                        description=desc,
                        remediation="Remove or restrict access to this file/endpoint.",
                        cvss=cvss, confidence="high",
                    )
                    if added:
                        self.ui.find(severity, title, url)
                        found += 1
                time.sleep(self.delay)
            except Exception:
                continue

        self.ui.ok(f"Nuclei checks complete — {found} finding(s)")


# ─── IDOR Module ───────────────────────────────────────────────────────────────