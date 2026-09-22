"""
DeserializationModule — GhostRecon module.
Detects insecure deserialization signatures in cookies and headers.
"""
import re
import urllib.parse
import base64

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class DeserializationModule(BaseModule):
    NAME = "Deserialization"

    def run(self):
        self.ui.section("Insecure Deserialization Detection")
        if not requests:
            return

        s = self._session()
        try:
            resp = s.get(self.base_url, timeout=self.timeout)
        except Exception:
            return

        found = 0

        # Signatures
        # Java: rO0AB (base64 of hex aced0005)
        # .NET: /wEP (base64 of MAC/ViewState), AAEAAAD (base64)
        # PHP: O:\d+: (e.g. O:4:"User")
        
        signatures = [
            (r'^rO0AB', "Java Object Serialization (Base64)"),
            (r'^/wEP', ".NET ViewState (Base64)"),
            (r'^AAEAAAD', ".NET Serialization (Base64)"),
            (r'O:\d+:"', "PHP Object Serialization")
        ]

        def check_value(val, location, key):
            try:
                # Try url-decoding first
                decoded = urllib.parse.unquote(val)
                for sig, name in signatures:
                    if re.search(sig, decoded):
                        return name
                        
                # Try base64 decoding if it looks like b64
                if len(decoded) % 4 == 0 and re.match(r'^[a-zA-Z0-9+/]+={0,2}$', decoded):
                    b64_decoded = base64.b64decode(decoded).decode('utf-8', errors='ignore')
                    for sig, name in signatures:
                         if re.search(sig, b64_decoded):
                             return name
            except Exception:
                pass
            return None

        # Check cookies
        for cookie in s.cookies:
            match = check_value(cookie.value, "Cookie", cookie.name)
            if match:
                 self.db.add(
                    title=f"Serialized Object Detected ({match})",
                    severity="medium", url=self.base_url, module=self.NAME,
                    description=(
                        f"A serialized object was detected in the '{cookie.name}' cookie. "
                        "If the server deserializes this object without verification, it may lead to Remote Code Execution."
                    ),
                    remediation="Avoid deserializing untrusted data. Use safe data formats like JSON instead of native language serialization.",
                    cvss="5.3",
                    confidence="MEDIUM",
                    confidence_score=60,
                    validation_steps=["signature_matched"],
                    evidence=[f"Cookie: {cookie.name}={cookie.value}"]
                )
                 self.ui.find("medium", f"Serialized Object ({match})", f"Cookie: {cookie.name}")
                 found += 1

        if found == 0:
            self.ui.info("No serialized objects detected in HTTP responses.")
