"""
DeserializationModule — GhostRecon module.
Detects insecure deserialization signatures in cookies, response headers,
and JSON API response bodies (purely passive signature matching — this
module never sends active gadget-chain payloads, since a Java/.NET/PHP
gadget aimed at the wrong runtime is pure noise; it flags where a serialized
blob was OBSERVED, which is a necessary precondition for the vuln, not the
vuln itself, hence the MEDIUM confidence throughout).
"""
import re
import urllib.parse
import base64

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


# Java: rO0AB (base64 of hex aced0005)
# .NET: /wEP (base64 ViewState prefix), AAEAAAD (base64 BinaryFormatter header)
# PHP:  O:\d+:"ClassName" (object) or a:\d+:{ (array) — both are unserialize() targets
SIGNATURES = [
    (r'^rO0AB', "Java Object Serialization (Base64)"),
    (r'^/wEP', ".NET ViewState (Base64)"),
    (r'^AAEAAAD', ".NET BinaryFormatter (Base64)"),
    (r'O:\d+:"[A-Za-z_][A-Za-z0-9_\\]*":\d+:\{', "PHP Object Serialization"),
    (r'^a:\d+:\{', "PHP Array Serialization"),
]


def _check_value(val: str):
    """Return a signature name if `val` looks like a serialized blob, else None."""
    if not val or len(val) < 6:
        return None
    try:
        decoded = urllib.parse.unquote(val)
        for sig, name in SIGNATURES:
            if re.search(sig, decoded):
                return name

        if len(decoded) % 4 == 0 and re.match(r'^[a-zA-Z0-9+/]{8,}={0,2}$', decoded):
            b64_decoded = base64.b64decode(decoded).decode('utf-8', errors='ignore')
            for sig, name in SIGNATURES:
                if re.search(sig, b64_decoded):
                    return name
    except Exception:
        pass
    return None


# Response headers unlikely to ever legitimately carry a serialized blob are
# skipped — scanning every header on every response is wasted work.
INTERESTING_HEADERS = [
    "set-cookie", "x-session-data", "x-session-token", "x-auth-token",
    "x-viewstate", "x-state", "authorization", "x-user-data",
]


class DeserializationModule(BaseModule):
    NAME = "Deserialization"

    def run(self):
        self.ui.section("Insecure Deserialization Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        seen_locations = set()

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]
        for endpoint in endpoints:
            try:
                resp = s.get(endpoint, timeout=self.timeout)
            except Exception:
                continue
            found += self._scan_response(resp, endpoint, seen_locations)

        # JSON API responses — a serialized token embedded as a string value
        # in a JSON body (e.g. {"session": "rO0AB..."}) is a common pattern
        # this scanner would otherwise never see, since it only lives inside
        # a JSON field, not a cookie or a whole-response header.
        for api_ep in self.ctx.get("api_endpoints", []):
            try:
                headers = {name: str(example) for name, example in api_ep.get("header_params", []) if example}
                method = api_ep.get("method", "GET")
                body = {p: "test" for p in api_ep.get("json_props", [])} if api_ep.get("json_props") else None
                resp = s.request(method, api_ep["url"], json=body, headers=headers, timeout=self.timeout)
            except Exception:
                continue
            found += self._scan_json_body(resp, api_ep["url"], seen_locations)

        if found == 0:
            self.ui.info("No serialized objects detected in HTTP responses.")

    def _scan_response(self, resp, url, seen_locations):
        found = 0
        for cookie in resp.cookies:
            found += self._report_if_match(cookie.value, "Cookie", cookie.name, url, seen_locations)
        for header_name, header_value in resp.headers.items():
            if header_name.lower() in INTERESTING_HEADERS:
                found += self._report_if_match(header_value, "Header", header_name, url, seen_locations)
        return found

    def _scan_json_body(self, resp, url, seen_locations):
        try:
            data = resp.json()
        except Exception:
            return 0
        found = 0
        for key, value in self._flatten_json_strings(data):
            found += self._report_if_match(value, "JSON field", key, url, seen_locations)
        return found

    @staticmethod
    def _flatten_json_strings(data, prefix="", depth=0):
        """Yield (key_path, value) for every string leaf in a JSON structure, capped at depth 4."""
        if depth > 4:
            return
        if isinstance(data, dict):
            for k, v in data.items():
                yield from DeserializationModule._flatten_json_strings(v, f"{prefix}.{k}" if prefix else k, depth + 1)
        elif isinstance(data, list):
            for i, v in enumerate(data[:10]):
                yield from DeserializationModule._flatten_json_strings(v, f"{prefix}[{i}]", depth + 1)
        elif isinstance(data, str):
            yield (prefix, data)

    def _report_if_match(self, value, location_type, key, url, seen_locations):
        match = _check_value(value)
        if not match:
            return 0

        dedup_key = (location_type, key, match)
        if dedup_key in seen_locations:
            return 0
        seen_locations.add(dedup_key)

        self.db.add(
            title=f"Serialized Object Detected ({match})",
            severity="medium", url=url, module=self.NAME,
            description=(
                f"A serialized object was detected in {location_type.lower()} '{key}' at {url}. "
                "If the server deserializes this value without verification, it may lead to "
                "Remote Code Execution via a gadget chain (e.g. ysoserial for Java, "
                "ViewState gadgets for .NET, PHP Object Injection via __wakeup/__destruct)."
            ),
            remediation=(
                "Avoid deserializing untrusted data with native language serializers "
                "(Java ObjectInputStream, PHP unserialize(), .NET BinaryFormatter). "
                "Use safe data formats like JSON, and if native serialization is required, "
                "sign/HMAC the payload and verify before deserializing."
            ),
            cvss="5.3",
            confidence="MEDIUM",
            confidence_score=60,
            validation_steps=["signature_matched"],
            evidence=[f"{location_type}: {key} = {value[:200]}"],
            references=[
                "https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data",
                "https://github.com/frohoff/ysoserial",
            ],
        )
        self.ui.find("medium", f"Serialized Object ({match}) in {location_type} '{key}'", url)
        return 1
