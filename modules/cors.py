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
                    severity = "high" if (acac.lower() == "true" and acao != "*") else "medium"
                    self.db.add(
                        title=f"CORS Misconfiguration — Reflected Origin: {acao}",
                        severity=severity, url=self.base_url, module=self.NAME,
                        description=(
                            f"The server reflects the attacker-controlled origin '{origin}' in "
                            f"Access-Control-Allow-Origin. With credentials: {acac}. "
                            "This allows cross-origin requests to read authenticated responses."
                        ),
                        remediation=(
                            "Whitelist only trusted origins. Never reflect the Origin header blindly. "
                            "Do not combine Access-Control-Allow-Credentials: true with wildcard origins."
                        ),
                        cvss="7.4" if severity == "high" else "5.4",
                        confidence="high",
                    )
                    self.ui.find(severity, f"CORS Misconfiguration ({acao})", self.base_url)
                    break
                time.sleep(self.delay)
            except Exception:
                continue


# ─── SSRF Module ───────────────────────────────────────────────────────────────