"""
NoSQLModule — GhostRecon module.
Detects NoSQL injection via operator injection ($gt, $ne).
"""
import json
import time
import urllib.parse
import hashlib

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


def _qjoin(endpoint: str, query_suffix: str) -> str:
    """Append a raw query suffix to an endpoint that may already have its
    own query string (recon.py seeds endpoints like /index.php?id=1 —
    blindly appending '?param=value' would double up the '?' and the
    payload would never reach the target parameter)."""
    sep = "&" if "?" in endpoint else "?"
    return f"{endpoint}{sep}{query_suffix}"


class NoSQLModule(BaseModule):
    NAME = "NoSQL Injection"

    def run(self):
        self.ui.section("NoSQL Injection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        # self.validator is provided by BaseModule.__init__ for every module.

        # API endpoints from an OpenAPI/Swagger spec (recon.py) — this is the
        # highest-signal path: real, confirmed JSON operations rather than a
        # keyword guess on the URL (the keyword filter below, e.g. requiring
        # "login"/"auth"/"user"/"search"/"api" in the endpoint string, would
        # have completely missed a real endpoint like POST /tokens — no match
        # on any of those substrings — which is exactly the class of endpoint
        # this vuln lives on in practice).
        found += self._test_api_endpoints(s)

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:20]

        for endpoint in endpoints:
            # Skip likely static assets
            if endpoint.endswith((".jpg", ".png", ".js", ".css", ".html")):
                continue

            # We need endpoints that accept parameters. Let's test URL params and JSON body
            # For simplicity, we'll test common auth/search endpoints if present
            if any(x in endpoint for x in ["login", "auth", "search", "user", "api"]):
                # 1. URL Parameter Injection
                # Normally we'd look for ?user=admin. We simulate an injected request: ?user[$ne]=invalid
                payload_url = _qjoin(endpoint, "username[$ne]=ghostrecon&password[$ne]=ghostrecon")
                baseline_url = _qjoin(endpoint, "username=ghostrecon&password=ghostrecon")

                try:
                    resp_base = s.get(baseline_url, timeout=self.timeout)
                    resp_payload = s.get(payload_url, timeout=self.timeout)

                    base_hash = hashlib.md5(resp_base.text.encode()).hexdigest()
                    payload_hash = hashlib.md5(resp_payload.text.encode()).hexdigest()

                    # Differential analysis: if the response differs significantly when using NoSQL operators
                    if base_hash != payload_hash and abs(len(resp_base.text) - len(resp_payload.text)) > 50:
                        # Ensure it's not just a general error page difference
                        if resp_payload.status_code in [200, 201, 301, 302]:
                            self.db.add(
                                title="NoSQL Injection — Operator Injection in URL",
                                severity="high", url=endpoint, module=self.NAME,
                                description=(
                                    "Endpoint exhibits different behavior when MongoDB operators ($ne) are used "
                                    "in query parameters. This strongly suggests a NoSQL injection vulnerability."
                                ),
                                remediation="Sanitize input and do not pass raw user input objects directly to NoSQL queries.",
                                cvss="8.5",
                                confidence="HIGH",
                                confidence_score=80,
                                validation_steps=["differential_analysis"],
                                evidence=[f"Payload URL: {payload_url}"]
                            )
                            self.ui.find("high", "NoSQL Injection (URL)", endpoint)
                            found += 1
                except Exception:
                    pass

                # 2. JSON Body Injection (if endpoint accepts POST)
                json_payload = {"username": {"$ne": "ghostrecon"}, "password": {"$ne": "ghostrecon"}}
                json_baseline = {"username": "ghostrecon", "password": "ghostrecon"}
                headers = {"Content-Type": "application/json"}

                try:
                    resp_base = s.post(endpoint, json=json_baseline, headers=headers, timeout=self.timeout)
                    resp_payload = s.post(endpoint, json=json_payload, headers=headers, timeout=self.timeout)

                    base_hash = hashlib.md5(resp_base.text.encode()).hexdigest()
                    payload_hash = hashlib.md5(resp_payload.text.encode()).hexdigest()

                    if base_hash != payload_hash and abs(len(resp_base.text) - len(resp_payload.text)) > 50:
                        if resp_payload.status_code in [200, 201, 301, 302] and resp_base.status_code != resp_payload.status_code:
                             self.db.add(
                                title="NoSQL Injection — Operator Injection in JSON",
                                severity="critical", url=endpoint, module=self.NAME,
                                description=(
                                    "Endpoint exhibits authentication bypass or data disclosure when MongoDB operators "
                                    "are used in JSON payloads. The response status changed from "
                                    f"{resp_base.status_code} (baseline) to {resp_payload.status_code} (payload)."
                                ),
                                remediation="Sanitize input and enforce strict schema validation for JSON APIs.",
                                cvss="9.1",
                                confidence="CONFIRMED",
                                confidence_score=90,
                                validation_steps=["differential_analysis_status_change"],
                                evidence=[f"Payload: {json.dumps(json_payload)}"]
                            )
                             self.ui.find("critical", "NoSQL Injection (JSON)", endpoint)
                             found += 1
                except Exception:
                    pass

            time.sleep(self.delay)

        if found == 0:
            self.ui.info("No NoSQL Injection vulnerabilities detected.")

    def _test_api_endpoints(self, s) -> int:
        """
        Test JSON body properties from an OpenAPI/Swagger spec for MongoDB
        operator injection.

        Earlier version routed this through Validator.differential_test with
        a plain-STRING baseline_value and an OBJECT-shaped operator payload.
        On any target with basic OpenAPI/JSON-schema request validation (very
        common — e.g. connexion, FastAPI, express-openapi-validator), sending
        an object where a string is declared gets rejected by the schema
        validator itself (400 "not of type 'string'") *regardless of whether
        a NoSQL backend exists at all*. That divergence from the string
        baseline was being reported as CRITICAL NoSQL injection — verified as
        a real false positive against a live (SQLite-backed, no NoSQL engine
        in sight) target this session: both operator probes below produced
        byte-for-byte-structurally-identical 400 schema-rejection responses.

        Fixed by comparing two OBJECT-shaped probes against each other (same
        JSON type as each other, so a type-only schema rejection treats both
        identically and produces no differential), varying only the
        operator's semantics: `$gt: ""` matches virtually any non-empty
        string if evaluated, `$eq: <impossible value>` matches nothing. A
        real difference between them can only come from the backend actually
        evaluating the operator — never from JSON-schema type validation.
        """
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})

        for api_ep in self.ctx.get("api_endpoints", []):
            method = api_ep.get("method", "POST")
            url = api_ep.get("url")
            json_props = api_ep.get("json_props", [])
            if not url or not json_props:
                continue

            headers = dict(auth_headers)
            for name, example in api_ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            for prop in json_props:
                other = {p: "ghostrecon_value" for p in json_props if p != prop}

                def send(op_value, _other=other, _prop=prop, _url=url, _method=method, _headers=headers):
                    body = {**_other, _prop: op_value}
                    try:
                        return s.request(_method, _url, json=body, headers=_headers, timeout=self.timeout)
                    except Exception:
                        return None

                true_resp  = send({"$gt": ""})
                false_resp = send({"$eq": "ghostrecon_impossible_9f3ae2"})
                if true_resp is None or false_resp is None:
                    continue

                same_status = true_resp.status_code == false_resp.status_code
                same_shape  = (self.validator._structural_hash(true_resp.text) ==
                               self.validator._structural_hash(false_resp.text))
                if same_status and same_shape:
                    continue  # identically treated -> operator was never evaluated

                # Confirm with a control repeat of the "true" probe before reporting.
                control_resp = send({"$gt": ""})
                if control_resp is None:
                    continue
                control_matches_true = (
                    control_resp.status_code == true_resp.status_code and
                    self.validator._structural_hash(control_resp.text) == self.validator._structural_hash(true_resp.text)
                )
                if not control_matches_true:
                    continue  # not stable -> don't report

                self.db.add(
                    title=f"NoSQL Injection — Operator Injection in '{prop}' (JSON body)",
                    severity="high", url=url, module=self.NAME,
                    description=(
                        f"JSON body property '{prop}' behaves differently, in a stable/repeatable "
                        "way, when sent a MongoDB query operator ($gt vs. $eq-impossible) instead "
                        "of a plain scalar — indicating the value is passed unsanitized into a "
                        "NoSQL query rather than being rejected by schema validation."
                    ),
                    remediation=(
                        "Enforce strict JSON schema validation — reject non-scalar (object/array) "
                        "values for fields that should only ever be strings/numbers — before "
                        "passing input to the query layer."
                    ),
                    cvss="8.5",
                    confidence="HIGH", confidence_score=80,
                    validation_steps=["operator_pair_differential", "control_repeat"],
                    evidence=[
                        f"$gt probe: status={true_resp.status_code}, {len(true_resp.text)}b",
                        f"$eq-impossible probe: status={false_resp.status_code}, {len(false_resp.text)}b",
                    ],
                )
                self.ui.find("high", f"NoSQL Injection via '{prop}' JSON body", url)
                found += 1

                if found > 5:
                    return found
        return found
