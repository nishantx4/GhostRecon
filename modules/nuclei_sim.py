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
        self.ui.section("Nuclei — Vulnerability Scanning")
        if not requests:
            return

        # Check if real Nuclei is available
        from core.tool_runner import ExternalToolRunner
        runner = ExternalToolRunner(self.ui)
        if runner.is_installed("nuclei"):
            self.ui.info("Running real Nuclei scanner...")
            # We use nuclei asynchronously in the TUI, but here we do a sync fallback
            # We won't block the whole scan on nuclei unless it's headless.
            # A better approach is the session orchestrator handling it.
            # For now, we'll just run a fast nuclei scan on the base URL.
            args = ["-u", self.base_url, "-t", "cves,exposures", "-j"]
            result = runner.run_sync("nuclei", args, timeout=120)
            
            if result.success and result.parsed_results:
                for item in result.parsed_results:
                    info = item.get("info", {})
                    severity = info.get("severity", "info").lower()
                    if severity not in ["critical", "high", "medium", "low", "info"]:
                        severity = "info"
                        
                    self.db.add(
                        title=info.get("name", "Nuclei Finding"),
                        severity=severity,
                        url=item.get("matched-at", self.base_url),
                        module=self.NAME,
                        description=info.get("description", ""),
                        remediation=info.get("remediation", ""),
                        cvss=str(info.get("classification", {}).get("cvss-metrics", "")),
                        confidence="HIGH",
                        confidence_score=85,
                        validation_steps=["nuclei_verified"],
                        external_tool="nuclei"
                    )
                    self.ui.find(severity, info.get("name", "Finding"), item.get("matched-at", self.base_url))
                return
            elif result.success:
                self.ui.info("Nuclei found no vulnerabilities.")
                return

        # Fallback to internal checks
        self.ui.info("Running built-in common vulnerability checks...")
        
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        baseline = self.ctx.get('baseline_profile')

        for path, title, severity, cvss, desc in self.CHECKS:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)
                if resp.status_code in (200, 206):
                    body = resp.text
                    ct = resp.headers.get("Content-Type", "")
                    
                    # FP Check: Soft-404
                    if baseline and baseline.matches_soft_404(body, resp.status_code):
                        continue
                        
                    # FP Check: HTML masquerading
                    is_html = "text/html" in ct or "<html" in body.lower()[:100]
                    
                    # Content validation rules per path
                    valid = False
                    if path.startswith("/.env") and not is_html:
                        valid = any(x in body for x in ["APP_", "DB_", "SECRET", "KEY="])
                    elif path.endswith((".zip", ".tar.gz", ".bak", ".sqlite", ".db")) and not is_html:
                        valid = len(resp.content) > 100
                    elif path == "/.git/HEAD" and not is_html:
                        valid = "ref: refs/heads" in body
                    elif path == "/phpinfo.php":
                        valid = "<title>phpinfo()</title>" in body or "PHP Version" in body
                    elif path == "/server-status":
                        valid = "Apache Server Status" in body
                    elif path.endswith(".html") or path.endswith("/"):
                        # Allowed to be HTML
                        valid = len(body) > 10
                    elif not is_html:
                        valid = len(body) > 10
                        
                    if not valid:
                        continue
                        
                    added = self.db.add(
                        title=title, severity=severity, url=url, module=self.NAME,
                        description=desc,
                        remediation="Remove or restrict access to this file/endpoint.",
                        cvss=cvss, confidence="HIGH", confidence_score=85,
                        validation_steps=["status_200", "content_validated", "soft_404_checked"]
                    )
                    if added:
                        self.ui.find(severity, title, url)
                        found += 1
                time.sleep(self.delay)
            except Exception:
                continue

        self.ui.ok(f"Nuclei built-in checks complete — {found} finding(s)")


# ─── IDOR Module ───────────────────────────────────────────────────────────────