"""
SSTIModule — GhostRecon module.
Detects Server-Side Template Injection via math evaluation probes.
"""
import re
import time
import urllib.parse

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


class SSTIModule(BaseModule):
    NAME = "SSTI"

    # Probes: (payload, expected_output, engine_hint)
    PROBES = [
        ("{{7*7}}",       "49",      "Jinja2/Twig/Nunjucks"),
        ("${7*7}",        "49",      "Freemarker/Velocity/Mako"),
        ("<%=7*7%>",      "49",      "ERB/EJS"),
        ("#{7*7}",        "49",      "Ruby/Pebble"),
        ("${{7*7}}",      "49",      "Thymeleaf"),
        ("{{7*'7'}}",     "7777777", "Jinja2 (string multiplication)"),
        ("{*7*7*}",       "49",      "Smarty"),
    ]

    SSTI_PARAMS = [
        "name", "template", "page", "view", "content", "text", "msg",
        "message", "title", "body", "desc", "description", "value",
        "search", "q", "query", "input", "data", "comment", "email",
    ]

    def run(self):
        self.ui.section("SSTI — Server-Side Template Injection Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]
        test_params = set(self.SSTI_PARAMS)
        for ep in self.ctx.get("discovered_params", []):
            if isinstance(ep, dict):
                test_params.update(ep.get("params", {}).keys())

        for endpoint in endpoints:
            for param in test_params:
                # First, get baseline to check if "49" naturally appears
                baseline_url = _qjoin(endpoint, f"{param}=ghostrecon_baseline_test")
                try:
                    baseline_resp = s.get(baseline_url, timeout=self.timeout)
                    baseline_text = baseline_resp.text
                except Exception:
                    continue

                for payload, expected, engine in self.PROBES:
                    probe_url = _qjoin(endpoint, f"{param}={urllib.parse.quote(payload)}")
                    try:
                        resp = s.get(probe_url, timeout=self.timeout)

                        # Check if expected output appears in payload response
                        if expected in resp.text:
                            # Critical FP check: does the expected output also appear in baseline?
                            if expected in baseline_text:
                                # "49" appears naturally in the page — can't confirm SSTI
                                continue

                            # Additional check: the payload itself shouldn't appear literally
                            # (some apps just reflect input unchanged)
                            if payload in resp.text:
                                # Payload reflected literally — check if expected also appears separately
                                # Remove all payload reflections and check again
                                cleaned = resp.text.replace(payload, "")
                                if expected not in cleaned:
                                    continue

                            self.db.add(
                                title=f"SSTI — Template Injection via '{param}' ({engine})",
                                severity="critical", url=endpoint, module=self.NAME,
                                description=(
                                    f"Parameter '{param}' is vulnerable to Server-Side Template Injection. "
                                    f"Payload '{payload}' was evaluated to '{expected}' by the template engine "
                                    f"(likely {engine}). This can lead to Remote Code Execution."
                                ),
                                remediation=(
                                    "Never pass user input directly to template engines. "
                                    "Use sandboxed template rendering and strict input validation. "
                                    "Consider using logic-less templates (Mustache) for user-generated content."
                                ),
                                cvss="9.8",
                                confidence="CONFIRMED",
                                confidence_score=95,
                                validation_steps=["baseline_checked", "math_evaluated", "not_literal_reflection"],
                                evidence=[f"Payload: {payload}", f"Expected: {expected}", f"Engine: {engine}"],
                            )
                            self.ui.find("critical", f"SSTI via '{param}' ({engine})", endpoint)
                            found += 1
                            break  # One confirmed probe per param is enough

                        time.sleep(self.delay)
                    except Exception:
                        continue

                if found > 10:
                    break
            if found > 10:
                break

        # API endpoints from an OpenAPI/Swagger spec (recon.py) — a JSON REST
        # API has no query-string surface for the loop above to find; SSTI in
        # a JSON field (e.g. a templated notification/email body) is common
        # and otherwise completely invisible to this module.
        found += self._test_api_endpoints(s)

        # Check for template error messages (lower confidence)
        if found == 0:
            self._check_template_errors(s, endpoints, test_params)

        if found == 0:
            self.ui.info("No SSTI vulnerabilities detected.")

    def _test_api_endpoints(self, s) -> int:
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
                other = {p: "test" for p in json_props if p != prop}
                try:
                    base_resp = s.request(method, url, timeout=self.timeout, headers=headers,
                                           json={**other, prop: "ghostrecon_baseline_test"})
                    baseline_text = base_resp.text
                except Exception:
                    baseline_text = ""

                for payload, expected, engine in self.PROBES:
                    try:
                        resp = s.request(method, url, timeout=self.timeout, headers=headers,
                                          json={**other, prop: payload})
                    except Exception:
                        continue

                    if expected in resp.text:
                        if expected in baseline_text:
                            continue
                        if payload in resp.text:
                            cleaned = resp.text.replace(payload, "")
                            if expected not in cleaned:
                                continue

                        self.db.add(
                            title=f"SSTI — Template Injection via '{prop}' (JSON body, {engine})",
                            severity="critical", url=url, module=self.NAME,
                            description=(
                                f"JSON body property '{prop}' is vulnerable to Server-Side Template Injection. "
                                f"Payload '{payload}' was evaluated to '{expected}' by the template engine "
                                f"(likely {engine}). This can lead to Remote Code Execution."
                            ),
                            remediation=(
                                "Never pass user input directly to template engines. "
                                "Use sandboxed template rendering and strict input validation."
                            ),
                            cvss="9.8",
                            confidence="CONFIRMED",
                            confidence_score=95,
                            validation_steps=["baseline_checked", "math_evaluated", "not_literal_reflection"],
                            evidence=[f"Payload: {payload}", f"Expected: {expected}", f"Engine: {engine}"],
                        )
                        self.ui.find("critical", f"SSTI via '{prop}' JSON body ({engine})", url)
                        found += 1
                        break
                    time.sleep(self.delay)

                if found > 5:
                    return found
        return found

    def _check_template_errors(self, s, endpoints, params):
        """Check for template engine error messages (weaker signal)."""
        error_patterns = [
            (r"TemplateSyntaxError", "Jinja2/Django"),
            (r"Twig_Error_Syntax", "Twig"),
            (r"freemarker\.template", "Freemarker"),
            (r"org\.apache\.velocity", "Velocity"),
            (r"mako\.exceptions", "Mako"),
            (r"pebble\.error", "Pebble"),
            (r"smarty.*error", "Smarty"),
        ]

        for endpoint in endpoints[:10]:
            for param in list(params)[:5]:
                url = _qjoin(endpoint, f"{param}={urllib.parse.quote('{{invalid_syntax_!@#}}')}")
                try:
                    resp = s.get(url, timeout=self.timeout)
                    for pattern, engine in error_patterns:
                        if re.search(pattern, resp.text, re.IGNORECASE):
                            self.db.add(
                                title=f"SSTI Potential — {engine} Error Disclosure via '{param}'",
                                severity="medium", url=endpoint, module=self.NAME,
                                description=(
                                    f"Template engine error ({engine}) was triggered by malformed template syntax "
                                    f"in parameter '{param}'. This suggests the parameter is processed by a "
                                    "template engine and may be exploitable."
                                ),
                                remediation="Investigate template processing of user input in this parameter.",
                                cvss="7.2",
                                confidence="MEDIUM",
                                confidence_score=60,
                                validation_steps=["error_pattern_matched"],
                            )
                            self.ui.find("medium", f"SSTI Potential — {engine} error via '{param}'", endpoint)
                            return
                except Exception:
                    continue
