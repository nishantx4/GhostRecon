"""
SecretsModule — GhostRecon module.

Probes for sensitive files and, when one is reachable, scores the content
(Shannon entropy + secret-looking patterns) and optionally asks AI whether
it holds a real secret before reporting, to keep false positives low.
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


# Patterns that look like live credentials / keys.
SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),                       # AWS access key
    re.compile(r"(?i)secret[_-]?key\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)api[_-]?key\s*[=:]\s*\S{8,}"),
    re.compile(r"(?i)password\s*[=:]\s*\S{4,}"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)mongodb(?:\+srv)?://\S+:\S+@"),
    re.compile(r"(?i)postgres://\S+:\S+@"),
    re.compile(r"ghp_[0-9A-Za-z]{36}"),                    # GitHub token
]


def _shannon_entropy(text):
    if not text:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


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
                    body = resp.text
                    pattern_hit = any(p.search(body) for p in SECRET_PATTERNS)
                    entropy = _shannon_entropy(body[:2000])

                    severity = "critical"
                    confidence = "high" if pattern_hit else "medium"
                    reason = "Pattern match" if pattern_hit else f"High-entropy content ({entropy:.1f})"

                    # Optional AI validation to weed out placeholder/example files.
                    if self.ai and self.ai.enabled:
                        try:
                            verdict = self.ai.validate_secret(label, body)
                            if verdict:
                                if not verdict.get("is_secret", True):
                                    # AI says it's not a real secret; downgrade, don't drop.
                                    severity = "low"
                                    confidence = verdict.get("confidence", "low")
                                    reason = verdict.get("reason", reason)
                                else:
                                    confidence = verdict.get("confidence", confidence)
                                    reason = verdict.get("reason", reason)
                        except Exception:
                            pass

                    self.db.add(
                        title=f"Sensitive File Exposed: {label} ({path})",
                        severity=severity, url=url, module=self.NAME,
                        description=(
                            f"Sensitive file '{path}' ({label}) is accessible without "
                            f"authentication. Assessment: {reason}."
                        ),
                        remediation=f"Remove '{path}' from the web root or restrict access via server config.",
                        cvss="9.8" if severity == "critical" else "4.0",
                        confidence=confidence,
                        evidence=[f"Entropy: {entropy:.2f}", f"Pattern match: {pattern_hit}"],
                    )
                    self.ui.find(severity, f"Exposed: {label}", url)
                time.sleep(self.delay)
            except Exception:
                continue


# --- Reporter Module --------------------------------------------------------
