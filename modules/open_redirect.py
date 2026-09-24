"""
OpenRedirectModule — GhostRecon module.
Detects unvalidated redirect/forward vulnerabilities.
"""
import time
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class OpenRedirectModule(BaseModule):
    NAME = "Open Redirect"

    REDIRECT_PARAMS = [
        "url", "redirect", "next", "return", "goto", "dest",
        "redirect_uri", "return_to", "continue", "target", "rurl",
        "returnUrl", "forward", "follow", "redirect_url", "return_url",
        "checkout_url", "login_url", "image_url", "success_url",
    ]

    CANARY_URLS = [
        "//ghostrecon-redirect-test.example.com",
        "https://ghostrecon-redirect-test.example.com",
        "/\\ghostrecon-redirect-test.example.com",
        "//ghostrecon-redirect-test.example.com%2f%2f",
        # {target} as fake userinfo, canary as the real authority — a naive
        # "starts with / contains our domain" whitelist check passes this,
        # but the browser navigates to the canary. (Previously had this
        # backwards — canary-as-userinfo/target-as-host — which resolves to
        # the *legitimate* target and can never trigger a canary match.)
        "https://{target}@ghostrecon-redirect-test.example.com",
        "////ghostrecon-redirect-test.example.com",
        "https:ghostrecon-redirect-test.example.com",
    ]

    def run(self):
        self.ui.section("Open Redirect — Unvalidated Redirect Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        s = self._session()
        found = 0
        canary_domain = "ghostrecon-redirect-test.example.com"

        endpoints = [self.base_url] + self.ctx.get("endpoints", [])[:30]

        for endpoint in endpoints:
            for param in self.REDIRECT_PARAMS:
                for canary_url in self.CANARY_URLS:
                    # Replace {target} placeholder with actual target
                    test_url = canary_url.replace("{target}", self.target)
                    full_url = f"{endpoint}?{param}={urllib.parse.quote(test_url, safe='')}"

                    try:
                        resp = s.get(full_url, timeout=self.timeout, allow_redirects=False)

                        # Check for redirect to our canary domain
                        location = resp.headers.get("Location", "")

                        if canary_domain in location:
                            self.db.add(
                                title=f"Open Redirect via '{param}' Parameter",
                                severity="medium", url=endpoint, module=self.NAME,
                                description=(
                                    f"Parameter '{param}' allows unvalidated redirects. "
                                    f"Injected URL '{test_url}' caused redirect to: {location}. "
                                    "This enables phishing, OAuth token theft, and SSO bypass attacks."
                                ),
                                remediation=(
                                    "Validate redirect targets against a whitelist of allowed domains. "
                                    "Use relative paths only, or maintain a mapping of allowed redirect keys."
                                ),
                                cvss="6.1",
                                confidence="CONFIRMED",
                                confidence_score=95,
                                validation_steps=["canary_in_location_header"],
                                evidence=[f"Location: {location}", f"Payload: {test_url}"],
                            )
                            self.ui.find("medium", f"Open Redirect via '{param}'", endpoint)
                            found += 1
                            break  # Found on this param, try next param

                        time.sleep(self.delay)
                    except Exception:
                        continue

                if found > 10:
                    break
            if found > 10:
                break

        found += self._test_json_bodies(s, canary_domain, found)

        if found == 0:
            self.ui.info("No open redirect vulnerabilities detected.")

    def _test_json_bodies(self, s, canary_domain, already_found):
        """
        OAuth-style redirect_uri / callback params are commonly delivered as
        JSON body properties on API-first targets, not query strings — check
        those too using ctx['api_endpoints'] from an OpenAPI/Swagger spec.
        """
        found = 0
        auth_headers = self.ctx.get("auth_headers", {})
        redirect_hints = [p.lower() for p in self.REDIRECT_PARAMS]

        for ep in self.ctx.get("api_endpoints", []):
            method = ep.get("method", "POST")
            if method not in ("POST", "PUT", "PATCH"):
                continue
            json_props = ep.get("json_props", [])
            candidates = [p for p in json_props if any(h in p.lower() for h in redirect_hints)]
            if not candidates:
                continue

            headers = dict(auth_headers)
            for name, example in ep.get("header_params", []):
                if example:
                    headers[name] = str(example)

            for prop in candidates:
                for canary_url in self.CANARY_URLS:
                    test_url = canary_url.replace("{target}", self.target)
                    body = {p: "test" for p in json_props if p != prop}
                    body[prop] = test_url
                    try:
                        resp = s.request(method, ep["url"], json=body, timeout=self.timeout,
                                          headers=headers, allow_redirects=False)
                        location = resp.headers.get("Location", "")
                        if canary_domain in location:
                            self.db.add(
                                title=f"Open Redirect via '{prop}' JSON Body Property",
                                severity="medium", url=ep["url"], module=self.NAME,
                                description=(
                                    f"JSON body property '{prop}' allows unvalidated redirects. "
                                    f"Injected URL '{test_url}' caused redirect to: {location}. "
                                    "This enables phishing, OAuth token theft, and SSO bypass attacks."
                                ),
                                remediation=(
                                    "Validate redirect targets against a whitelist of allowed domains."
                                ),
                                cvss="6.1", confidence="CONFIRMED", confidence_score=95,
                                validation_steps=["canary_in_location_header"],
                                evidence=[f"Location: {location}", f"Payload: {test_url}"],
                            )
                            self.ui.find("medium", f"Open Redirect via '{prop}' (JSON)", ep["url"])
                            found += 1
                            break
                        time.sleep(self.delay)
                    except Exception:
                        continue
                if found + already_found > 10:
                    return found
        return found
