"""
PrototypePollutionModule — GhostRecon module.
Detects server-side Prototype Pollution via JSON request bodies (the
primary real-world vector — deep-merge libraries like lodash.merge,
Express's qs, or hand-rolled recursive-assign helpers) and, as a
secondary/legacy vector, query-string bracket-notation payloads.

Detection approach: differential comparison against a shape-matched control.
A raw "did this cause a 500?" check (the previous approach) is extremely
false-positive prone — almost any unexpected nested object can crash a
strict endpoint for reasons that have nothing to do with prototype
pollution. Instead, every `__proto__`/`constructor.prototype` payload is
compared against a CONTROL payload with the exact same JSON shape and size,
but a harmless key name instead of a magic one. Only a payload that behaves
differently from its shape-matched control (crashes when the control
doesn't, or produces a structurally different response) is reported —
isolating the special key name as the actual cause.
"""
import random
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class PrototypePollutionModule(BaseModule):
    NAME = "Prototype Pollution"

    # (pollution key path, harmless control key path — same nesting depth)
    POLLUTION_KEYS = [
        (["__proto__", "ghostrecon_pp"], ["ghostreconHarmless", "ghostrecon_pp"]),
        (["constructor", "prototype", "ghostrecon_pp"], ["ghostreconOuter", "ghostreconInner", "ghostrecon_pp"]),
    ]

    def run(self):
        self.ui.section("Prototype Pollution Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        # 1. JSON body endpoints from an OpenAPI spec — the highest-signal
        # vector, since it targets real accepted request shapes.
        for api_ep in self.ctx.get("api_endpoints", []):
            if api_ep.get("json_props") and api_ep.get("method") in ("POST", "PUT", "PATCH"):
                if self._test_json_endpoint(s, api_ep):
                    found += 1

        # 2. Generic probes against crawled endpoints — JSON body (for APIs
        # without a spec) and legacy query-string bracket notation.
        tested_bases = set()
        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:15]
        for endpoint in endpoints:
            base = endpoint.split("?")[0]
            if base in tested_bases:
                continue
            tested_bases.add(base)

            if self._differential_json_test(s, base, "POST", {}, {}, base):
                found += 1
            if self._test_query_string(s, base):
                found += 1

        if found == 0:
            self.ui.info("No Prototype Pollution vulnerabilities detected.")

    # ─────────────────────────────────────────────────────────────────────
    def _test_json_endpoint(self, s, api_ep):
        url = api_ep["url"]
        method = api_ep["method"]
        headers = {name: str(example) for name, example in api_ep.get("header_params", []) if example}
        base_body = {p: "test" for p in api_ep.get("json_props", [])}
        return self._differential_json_test(s, url, method, base_body, headers, url)

    def _differential_json_test(self, s, url, method, base_body, headers, report_url):
        for pollute_path, control_path in self.POLLUTION_KEYS:
            marker = f"gr_pp_{random.randint(100000, 999999)}"

            pollute_body = self._deep_copy(base_body)
            control_body = self._deep_copy(base_body)
            self._set_nested(pollute_body, pollute_path, marker)
            self._set_nested(control_body, control_path, marker)

            try:
                resp_pollute = s.request(method, url, json=pollute_body, headers=headers, timeout=self.timeout)
                resp_control = s.request(method, url, json=control_body, headers=headers, timeout=self.timeout)
            except Exception:
                continue

            verdict = self._compare(resp_pollute, resp_control)
            if verdict:
                self._report(report_url, method, ".".join(pollute_path[:-1]), marker, verdict)
                return True
        return False

    def _test_query_string(self, s, base_url):
        marker = f"gr_pp_{random.randint(100000, 999999)}"
        try:
            resp_pollute = s.get(base_url, params={f"__proto__[{marker}]": "1"}, timeout=self.timeout)
            resp_control = s.get(base_url, params={f"ghostreconHarmless[{marker}]": "1"}, timeout=self.timeout)
        except Exception:
            return False

        verdict = self._compare(resp_pollute, resp_control)
        if verdict:
            self._report(base_url, "GET", "__proto__ (query string)", marker, verdict)
            return True
        return False

    # ─────────────────────────────────────────────────────────────────────
    def _compare(self, resp_pollute, resp_control):
        """Return a short human-readable verdict string if the pollution
        payload behaved differently from its shape-matched control, else None."""
        # Signal 1: the magic key crashes the app while the harmless,
        # identically-shaped control does not.
        if resp_pollute.status_code >= 500 and resp_control.status_code < 500:
            return f"__proto__ payload caused HTTP {resp_pollute.status_code}, harmless-shaped control returned {resp_control.status_code}"

        # Signal 2: structurally different response despite an
        # equal-shape/equal-size request body — same idea as the SQLi
        # differential test, applied to a pollution vs. control pair.
        if resp_pollute.status_code == resp_control.status_code:
            len_p, len_c = len(resp_pollute.text), len(resp_control.text)
            threshold = max(30, len_c * 0.05)
            if abs(len_p - len_c) > threshold:
                return (f"Same HTTP status ({resp_pollute.status_code}) but response length diverged: "
                        f"{len_p}b (polluted) vs {len_c}b (control), threshold {threshold:.0f}b")

        return None

    def _report(self, url, method, key_path, marker, verdict):
        self.db.add(
            title=f"Server-Side Prototype Pollution via '{key_path}'",
            severity="high", url=url, module=self.NAME,
            description=(
                f"A {method} request to {url} with a '{key_path}' key in the body/query "
                f"produced measurably different behavior than an identically-shaped request "
                f"using a harmless key name, indicating the server merges user-controlled "
                f"keys into an object without filtering '__proto__'/'constructor.prototype'. "
                f"{verdict}. Depending on how polluted properties are later read by the "
                f"application, this can lead to privilege escalation, denial of service, or "
                f"in some frameworks (e.g. gadget chains in template engines) remote code execution."
            ),
            remediation=(
                "Reject or strip '__proto__', 'constructor', and 'prototype' keys before merging "
                "user-controlled objects. Use `Object.create(null)` for maps built from user input, "
                "or a merge utility with prototype-pollution protection (e.g. lodash >= 4.17.21)."
            ),
            cvss="7.3",
            confidence="MEDIUM",
            confidence_score=65,
            evidence=[f"Marker: {marker}", verdict],
            references=[
                "https://portswigger.net/web-security/prototype-pollution",
                "https://learn.snyk.io/lesson/prototype-pollution/",
            ],
            validation_steps=["differential_vs_shape_matched_control"],
        )
        self.ui.find("high", f"Prototype Pollution via '{key_path}'", url)

    @staticmethod
    def _deep_copy(d):
        import copy
        return copy.deepcopy(d)

    @staticmethod
    def _set_nested(d, path, value):
        cur = d
        for i, key in enumerate(path):
            if i == len(path) - 1:
                cur[key] = value
            else:
                cur = cur.setdefault(key, {})
