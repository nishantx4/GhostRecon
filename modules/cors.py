"""
CORSModule — GhostRecon module.
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


class CORSModule(BaseModule):
    NAME = "CORS"

    def run(self):
        self.ui.section("CORS Misconfiguration Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        test_origins = [
            "https://evil.com",
            f"https://evil.{self.target}",
            f"https://{self.target}.evil.com",
            "null",
        ]
        s = self._session()

        for origin in test_origins:
            try:
                resp = s.get(self.base_url, headers={"Origin": origin}, timeout=self.timeout)
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                if acao == origin or acao == "*":
                    creds_allowed = acac.lower() == "true"

                    # ── FP Fix: Wildcard without credentials is standard for public APIs ──
                    if acao == "*" and not creds_allowed:
                        # This is normal for public APIs/CDNs — downgrade to info
                        self.db.add(
                            title="CORS: Wildcard Origin (Public API — Informational)",
                            severity="info", url=self.base_url, module=self.NAME,
                            description=(
                                "The server returns Access-Control-Allow-Origin: * without credentials. "
                                "This is standard behavior for public APIs and CDN resources. "
                                "No authentication data can be stolen via this configuration."
                            ),
                            remediation="No action needed if this is intentionally a public endpoint.",
                            cvss="0.0",
                            confidence="CONFIRMED",
                            confidence_score=100,
                        )
                        self.ui.find("info", "CORS: Wildcard (public, no credentials)", self.base_url)
                        break

                    # Reflected origin WITH credentials — actually dangerous
                    if creds_allowed and acao != "*":
                        severity = "high"
                        confidence_score = 90
                        description = (
                            f"The server reflects the attacker-controlled Origin header "
                            f"('{origin}') back in Access-Control-Allow-Origin AND sets "
                            f"Access-Control-Allow-Credentials: true. Any site can make "
                            f"authenticated cross-origin requests using the victim's cookies/"
                            f"session and read the response, leading to full account "
                            f"compromise via CSRF-like data theft."
                        )
                    elif acao == "null":
                        severity = "medium"
                        confidence_score = 75
                        description = (
                            f"The server reflects the 'null' Origin in Access-Control-Allow-Origin. "
                            f"'null' is sent by sandboxed iframes and data:/file: origins, so an "
                            f"attacker can trivially craft a page that satisfies this check and "
                            f"read cross-origin responses."
                            + (" Combined with Access-Control-Allow-Credentials: true, this exposes "
                               "authenticated data." if creds_allowed else "")
                        )
                    else:
                        severity = "medium"
                        confidence_score = 70
                        description = (
                            f"The server reflects the attacker-controlled Origin header "
                            f"('{origin}') back in Access-Control-Allow-Origin. While no "
                            f"credentials are exposed here, this still permits arbitrary "
                            f"cross-origin reads of any non-credentialed response data."
                        )

                    self.db.add(
                        title=f"CORS Misconfiguration — Reflected Origin: {acao}",
                        severity=severity, url=self.base_url, module=self.NAME,
                        description=description,
                        remediation=(
                            "Whitelist only trusted origins. Never reflect the Origin header blindly. "
                            "Do not combine Access-Control-Allow-Credentials: true with wildcard origins."
                        ),
                        cvss="7.4" if severity == "high" else "5.4",
                        confidence="HIGH" if creds_allowed else "MEDIUM",
                        confidence_score=confidence_score,
                        validation_steps=["origin_reflected", "credentials_checked"],
                    )
                    self.ui.find(severity, f"CORS Misconfiguration ({acao})", self.base_url)
                    break
                time.sleep(self.delay)
            except Exception:
                continue


# ─── SSRF Module ───────────────────────────────────────────────────────────────