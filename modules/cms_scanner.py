"""
CMSScannerModule — GhostRecon module.
Detects common CMS and checks for known vulnerable paths.
"""
import re
import time
import urllib.parse
import shutil

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class CMSScannerModule(BaseModule):
    NAME = "CMS Scanner"

    def run(self):
        self.ui.section("CMS Detection & Scanning")
        if not requests:
            return

        s = self._session()
        try:
            resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            return

        cms_detected = None
        version = None

        # 1. Detect CMS
        if "wp-content" in resp.text or "wp-includes" in resp.text:
            cms_detected = "WordPress"
            match = re.search(r'name="generator" content="WordPress (.*?)"', resp.text)
            if match:
                version = match.group(1)
        elif "Joomla" in resp.text or re.search(r'name="generator" content="Joomla', resp.text):
            cms_detected = "Joomla"
        elif "Drupal" in resp.text or "X-Drupal-Cache" in resp.headers:
            cms_detected = "Drupal"
            match = re.search(r'name="Generator" content="Drupal (.*?) ', resp.text)
            if match:
                version = match.group(1)

        if not cms_detected:
            self.ui.info("No common CMS (WordPress, Joomla, Drupal) detected.")
            return

        self.ui.info(f"Detected CMS: {cms_detected}" + (f" (Version: {version})" if version else ""))
        
        # Add informational finding for detection
        self.db.add(
            title=f"CMS Detected: {cms_detected}",
            severity="info", url=self.base_url, module=self.NAME,
            description=f"The application is built using {cms_detected} {version or ''}.",
            cvss="0.0",
            confidence="CONFIRMED",
            confidence_score=95
        )

        # 2. Check vulnerable paths
        paths_to_check = []
        if cms_detected == "WordPress":
            paths_to_check = [
                ("/wp-json/wp/v2/users", "User Enumeration API"),
                ("/xmlrpc.php", "XML-RPC API (Brute Force/Pingback)")
            ]
            if shutil.which("wpscan"):
                 self.ui.info("💡 WPScan is installed! Run it for a deeper WordPress analysis.")
        elif cms_detected == "Joomla":
            paths_to_check = [
                ("/configuration.php~", "Backup Configuration"),
                ("/administrator/manifests/files/joomla.xml", "Joomla XML Manifest")
            ]
        elif cms_detected == "Drupal":
            paths_to_check = [
                ("/CHANGELOG.txt", "Changelog (Version Disclosure)"),
                ("/core/install.php", "Install script")
            ]

        for path, desc in paths_to_check:
            try:
                url = urllib.parse.urljoin(self.base_url, path)
                check_resp = s.get(url, timeout=self.timeout)
                if check_resp.status_code == 200 and len(check_resp.text) > 10:
                    
                    # Prevent False Positives (e.g. 200 OK on homepage redirect)
                    if "text/html" in check_resp.headers.get("Content-Type", "") and path.endswith(".txt"):
                         continue # Soft 404
                         
                    # For WP users API, check for JSON response
                    if path == "/wp-json/wp/v2/users" and ("id" not in check_resp.text or "name" not in check_resp.text):
                         continue
                         
                    self.db.add(
                        title=f"{cms_detected} — {desc}",
                        severity="medium", url=url, module=self.NAME,
                        description=f"Sensitive CMS path '{path}' is accessible.",
                        remediation="Restrict access to this path.",
                        cvss="5.3",
                        confidence="HIGH",
                        confidence_score=85
                    )
                    self.ui.find("medium", f"CMS Path Exposed: {desc}", url)
            except Exception:
                pass
