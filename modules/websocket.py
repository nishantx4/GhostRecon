"""
WebSocketModule — GhostRecon module.
Detects Cross-Site WebSocket Hijacking (CSWSH) vulnerabilities.
"""
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class WebSocketModule(BaseModule):
    NAME = "WebSocket Security"

    def run(self):
        self.ui.section("WebSocket — CSWSH Detection")
        if not requests:
            return

        # Simple endpoint discovery
        ws_endpoints = []
        for ep in self.ctx.get("endpoints", []):
            if any(path in ep.lower() for path in ["/ws", "/websocket", "/socket.io", "/signalr"]):
                ws_endpoints.append(ep)

        if not ws_endpoints:
            self.ui.info("No common WebSocket endpoints discovered.")
            return

        s = self._session()
        found = 0

        for endpoint in ws_endpoints[:5]:
            # Convert http/https to ws/wss for the request path, though we'll send a standard HTTP upgrade request
            try:
                headers = {
                    "Connection": "Upgrade",
                    "Upgrade": "websocket",
                    "Sec-WebSocket-Version": "13",
                    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
                    "Origin": "https://ghostrecon-evil-origin.example.com"
                }
                
                resp = s.get(endpoint, headers=headers, timeout=self.timeout)

                # HTTP 101 Switching Protocols indicates the upgrade was accepted
                if resp.status_code == 101:
                    self.db.add(
                        title="Cross-Site WebSocket Hijacking (CSWSH)",
                        severity="high", url=endpoint, module=self.NAME,
                        description=(
                            "The WebSocket endpoint accepts cross-origin connections with an arbitrary Origin header. "
                            "If the WebSocket relies on ambient credentials (like cookies) for authentication, "
                            "an attacker can hijack the connection."
                        ),
                        remediation="Validate the Origin header during the WebSocket handshake. Ensure it matches the expected domain.",
                        cvss="7.4",
                        confidence="CONFIRMED",
                        confidence_score=95,
                        validation_steps=["ws_upgrade_accepted", "evil_origin_accepted"]
                    )
                    self.ui.find("high", "CSWSH Detected", endpoint)
                    found += 1
            except Exception:
                pass

        if found == 0:
            self.ui.info("No WebSocket vulnerabilities detected.")
