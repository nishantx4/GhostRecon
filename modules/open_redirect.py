"""
OpenRedirectModule — detects open redirects in redirect-style parameters.

Injects an external target into common redirect params and confirms the
server issues a 3xx Location (or a meta/JS redirect) pointing at the
attacker-controlled host.
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


REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "url", "next",
                   "return", "return_url", "returnto", "return_to", "dest",
                   "destination", "continue", "goto", "out", "target", "to",
                   "link", "forward", "callback", "checkout_url"]

EVIL = "evil.example.com"

# Payload variants that defeat naive same-host checks.
PAYLOADS = [
    f"https://{EVIL}/",
    f"//{EVIL}/",
    f"https:/{EVIL}/",
    f"https://{EVIL}%2f%2e%2e",
    f"/\\{EVIL}/",
    f"https://example.com.{EVIL}/",
]


class OpenRedirectModule(BaseModule):
    NAME = "Open Redirect"

    def run(self):
        self.ui.section("Open Redirect Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        targets = self._collect_targets()
        self.ui.info(f"Testing {len(targets)} redirect injection point(s)")
        found = 0

        for base, param in targets:
            for payload in PAYLOADS:
                url = f"{base}?{urllib.parse.urlencode({param: payload})}"
                try:
                    resp = s.get(url, timeout=self.timeout, allow_redirects=False)
                except Exception:
                    continue

                location = resp.headers.get("Location", "")
                redirected = False

                if resp.status_code in (301, 302, 303, 307, 308) and EVIL in location:
                    redirected = True
                elif EVIL in resp.text and re.search(
                    r'(?:http-equiv=["\']?refresh|location\.(?:href|replace)|window\.location)',
                    resp.text, re.I,
                ):
                    redirected = True

                if redirected:
                    self.db.add(
                        title=f"Open Redirect via '{param}'",
                        severity="medium", url=base, module=self.NAME,
                        description=(
                            f"The '{param}' parameter redirects users to an arbitrary external "
                            f"host. Payload `{payload}` sent the client to `{EVIL}`. Open "
                            "redirects enable phishing and can be chained to bypass OAuth "
                            "redirect_uri checks or SSRF allow-lists."
                        ),
                        remediation=(
                            "Validate redirect targets against an allow-list of relative paths or "
                            "trusted hosts. Reject absolute/protocol-relative URLs to other origins."
                        ),
                        cvss="6.1", confidence="high",
                        evidence=[f"Payload: {payload}", f"Location: {location}", f"PoC: {url}"],
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
                        ],
                    )
                    self.ui.find("medium", f"Open Redirect via '{param}'", base)
                    found += 1
                    break
                time.sleep(self.delay)

        if found == 0:
            self.ui.info("No open redirects confirmed.")
        else:
            self.ui.ok(f"Open redirect scan complete — {found} finding(s)")

    def _collect_targets(self):
        targets = []
        seen = set()

        for ep in self.ctx.get("endpoints", []):
            try:
                parsed = urllib.parse.urlparse(ep)
                base = parsed.scheme + "://" + parsed.netloc + parsed.path
                for param in urllib.parse.parse_qs(parsed.query):
                    if param.lower() in REDIRECT_PARAMS:
                        key = (base, param)
                        if key not in seen:
                            seen.add(key)
                            targets.append(key)
            except Exception:
                continue

        for param in REDIRECT_PARAMS:
            key = (self.base_url, param)
            if key not in seen:
                seen.add(key)
                targets.append(key)

        return targets
