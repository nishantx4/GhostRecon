"""
SecretsModule — GhostRecon module.
Probes for exposed sensitive files with multi-stage validation to prevent false positives.
"""
import re
import math
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


# ── Content validation patterns per file type ─────────────────────────────────
# Each entry: (path, label, expected_content_type_prefix, body_patterns_required)
# body_patterns_required: list of strings — at least 1 must appear in body for confirmation
SENSITIVE_FILES = [
    ("/.env",                  "Environment Variables",      "text/",
     ["=", "DB_", "API_", "SECRET", "KEY=", "PASSWORD", "TOKEN", "HOST="]),
    ("/.env.local",            "Local Environment Variables", "text/",
     ["=", "DB_", "API_", "SECRET", "KEY=", "PASSWORD", "TOKEN", "HOST="]),
    ("/.env.production",       "Production Env Variables",   "text/",
     ["=", "DB_", "API_", "SECRET", "KEY=", "PASSWORD", "TOKEN", "HOST="]),
    ("/.env.backup",           "Env Backup",                 "text/",
     ["=", "DB_", "API_", "SECRET", "KEY=", "PASSWORD", "TOKEN", "HOST="]),
    ("/config/database.yml",   "Database Config",            "text/",
     ["database:", "adapter:", "host:", "username:", "password:"]),
    ("/config/secrets.yml",    "Secrets Config",             "text/",
     ["secret_key_base:", "production:", "development:"]),
    ("/wp-config.php",         "WordPress Config",           "text/",
     ["DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST", "table_prefix"]),
    ("/config.php",            "PHP Config",                 "text/",
     ["<?php", "$config", "define(", "password", "database"]),
    ("/settings.py",           "Django Settings",            "text/",
     ["SECRET_KEY", "DATABASES", "INSTALLED_APPS", "DEBUG"]),
    ("/app/config/parameters.yml", "Symfony Config",         "text/",
     ["parameters:", "database_", "mailer_", "secret:"]),
    ("/database.yml",          "Database Config",            "text/",
     ["database:", "adapter:", "host:", "username:"]),
    ("/.htpasswd",             "Password File",              "text/",
     [":"]),  # htpasswd format: user:hash
    ("/id_rsa",                "Private SSH Key",            "text/",
     ["-----BEGIN", "PRIVATE KEY"]),
    ("/.ssh/id_rsa",           "Private SSH Key",            "text/",
     ["-----BEGIN", "PRIVATE KEY"]),
    ("/credentials",           "Credentials File",           "text/",
     ["aws_access_key_id", "aws_secret_access_key", "[default]"]),
    ("/secrets.json",          "Secrets JSON",               "application/json",
     ['"', "key", "secret", "password", "token"]),
    ("/config.json",           "Config JSON",                "application/json",
     ['"', ":"]),
    ("/application.properties", "Spring Boot Config",        "text/",
     ["spring.", "server.port", "datasource", "="]),
]


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

        # Get baseline profile if available
        baseline = self.ctx.get('baseline_profile')

        s = self._session()
        found = 0

        for path, label, expected_ct, body_patterns in SENSITIVE_FILES:
            url = urllib.parse.urljoin(self.base_url, path)
            try:
                resp = s.get(url, timeout=self.timeout, allow_redirects=False)

                if resp.status_code != 200:
                    time.sleep(self.delay)
                    continue

                body = resp.text
                ct = resp.headers.get("Content-Type", "")

                # ── FP Check 1: Content-Type validation ──
                # If server returns text/html for a .env file, it's likely
                # a SPA catch-all route or custom error page, NOT a real file exposure
                if self._is_html_response(ct, body) and expected_ct != "text/html":
                    if self.verbose:
                        self.ui.info(f"  Skipped {path} — HTML response for non-HTML file (SPA/error page)")
                    time.sleep(self.delay)
                    continue

                # ── FP Check 2: Soft-404 detection ──
                if baseline and baseline.matches_soft_404(body, 200):
                    if self.verbose:
                        self.ui.info(f"  Skipped {path} — matches soft-404 fingerprint")
                    time.sleep(self.delay)
                    continue

                # ── FP Check 3: Content pattern validation ──
                # Body must contain at least 1 expected pattern for this file type
                body_upper = body.upper() if body else ""
                body_check = body if body else ""
                pattern_matches = sum(
                    1 for p in body_patterns
                    if p.upper() in body_upper or p in body_check
                )

                if pattern_matches == 0:
                    if self.verbose:
                        self.ui.info(f"  Skipped {path} — no expected content patterns found")
                    time.sleep(self.delay)
                    continue

                # ── FP Check 4: Minimum content length ──
                if len(body.strip()) < 10:
                    time.sleep(self.delay)
                    continue

                # ── Passed all checks — calculate confidence ──
                if pattern_matches >= 3:
                    confidence = "CONFIRMED"
                    confidence_score = 95
                elif pattern_matches >= 2:
                    confidence = "HIGH"
                    confidence_score = 85
                else:
                    confidence = "MEDIUM"
                    confidence_score = 65

                self.db.add(
                    title=f"Sensitive File Exposed: {label} ({path})",
                    severity="critical", url=url, module=self.NAME,
                    description=(
                        f"Sensitive file '{path}' ({label}) is accessible without authentication. "
                        f"Matched {pattern_matches}/{len(body_patterns)} expected content patterns."
                    ),
                    remediation=f"Remove '{path}' from the web root or restrict access via server config.",
                    cvss="9.8",
                    confidence=confidence,
                    confidence_score=confidence_score,
                    validation_steps=["status_200", "content_type_validated", "pattern_matched", "soft_404_checked"],
                )
                self.ui.find("critical", f"Exposed: {label}", url)
                found += 1

                time.sleep(self.delay)
            except Exception:
                continue

        if found == 0:
            self.ui.info("No exposed sensitive files found.")

    def _is_html_response(self, content_type: str, body: str) -> bool:
        """Check if response is actually HTML (common SPA false positive source)."""
        ct_lower = content_type.lower()
        if "text/html" in ct_lower or "application/xhtml" in ct_lower:
            return True
        stripped = body.strip()[:200].lower()
        if stripped.startswith(("<!doctype", "<html", "<!doctype html")):
            return True
        # Check for common SPA root div
        if '<div id="root"' in body[:500] or '<div id="app"' in body[:500]:
            return True
        return False


# --- Reporter Module --------------------------------------------------------
