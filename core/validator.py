"""
Validator — Multi-stage false positive elimination engine.

Every module should call Validator methods before reporting findings.
Stages:
  1. Baseline comparison (soft-404, content-type, SPA filtering)
  2. Differential confirmation (canary → probe → control)
  3. Statistical timing verification (Z-score analysis)
  4. AI semantic verification (NVIDIA NIM structured evaluation)

Usage:
    validator = Validator(baseline_profile, ai_engine, ui)

    # Check if a file exposure is real
    if validator.validate_file_exposure(url, response, expected_type="text/plain"):
        db.add(finding)

    # Check if reflected input is exploitable XSS
    if validator.validate_reflection(url, param, payload, response, context="html_body"):
        db.add(finding)

    # Confidence scoring
    score = validator.compute_confidence(checks_passed, checks_total, verification_type)
"""

import re
import json
import hashlib
import time
import statistics
from typing import Any


def _json_shape_paths(data, prefix="$", depth=0):
    """
    Recursively describe a JSON value's *shape* (key paths + value types),
    not its values — so two structurally identical responses with different
    content (e.g. two successful logins for different users) still hash the
    same, while a genuinely different shape (a 401 error body vs. a 200
    success body) correctly diverges. Used by Validator._structural_hash to
    make differential comparison meaningful on JSON API responses, which
    otherwise contain no HTML tags for the tag-sequence hash to key off.
    """
    if depth > 6:
        return [f"{prefix}:{type(data).__name__}"]
    if isinstance(data, dict):
        if not data:
            return [f"{prefix}:empty_dict"]
        paths = []
        for k in sorted(data.keys(), key=str)[:50]:
            paths.extend(_json_shape_paths(data[k], f"{prefix}.{k}", depth + 1))
        return paths
    if isinstance(data, list):
        if not data:
            return [f"{prefix}:empty_list"]
        # Only the first element's shape + a length bucket — the hash
        # shouldn't depend on exactly how many items came back.
        return [f"{prefix}:list[{min(len(data), 50)}]"] + _json_shape_paths(data[0], f"{prefix}[]", depth + 1)
    return [f"{prefix}:{type(data).__name__}"]


class Validator:
    """Multi-stage false positive elimination engine."""

    def __init__(self, baseline=None, ai=None, ui=None, session_factory=None):
        """
        Args:
            baseline: BaselineProfile from baseline.py
            ai: AIEngine instance for semantic verification
            ui: UI instance for output
            session_factory: Callable that returns a requests.Session
        """
        self.baseline = baseline
        self.ai = ai
        self.ui = ui
        self._session_factory = session_factory

    def _session(self):
        if self._session_factory:
            return self._session_factory()
        try:
            import requests
            s = requests.Session()
            s.headers.update({"User-Agent": "Mozilla/5.0 GhostRecon/3.0"})
            s.verify = False
            return s
        except ImportError:
            return None

    def _get(self, url: str, timeout: int = 10, **kwargs):
        s = self._session()
        if not s:
            return None
        try:
            return s.get(url, timeout=timeout, **kwargs)
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 1: Baseline Comparison
    # ═══════════════════════════════════════════════════════════════════════════

    def is_soft_404(self, response_body: str, status_code: int = 200) -> bool:
        """Check if a response is a soft-404 (custom error page with 200 status)."""
        if not self.baseline:
            return False
        return self.baseline.matches_soft_404(response_body, status_code)

    def is_html_masquerading(self, content_type: str, body: str, expected_type: str) -> bool:
        """
        Check if a response claiming to be a file is actually an HTML page.
        Used for: secrets.py, nuclei_sim.py — prevents flagging SPA catch-all routes.
        """
        if not expected_type:
            return False
        # If Content-Type says HTML but we expected something else
        ct_lower = content_type.lower()
        if "text/html" in ct_lower or "application/xhtml" in ct_lower:
            return True
        # Body starts with HTML markers
        stripped = body.strip()[:100].lower()
        if stripped.startswith(("<!doctype", "<html", "<!doctype html")):
            return True
        return False

    def validate_file_exposure(
        self,
        url: str,
        response,
        expected_type: str = "text/plain",
        content_patterns: list[str] | None = None,
    ) -> dict:
        """
        Validate a suspected file exposure (/.env, /.git/HEAD, /backup.zip, etc.)

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "reason": str}
        """
        if response is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "No response"}

        body = response.text if hasattr(response, "text") else str(response)
        status = response.status_code if hasattr(response, "status_code") else 200
        ct = ""
        if hasattr(response, "headers"):
            ct = response.headers.get("Content-Type", "")

        # Check 1: Must be 200
        if status != 200:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": f"Status {status}"}

        # Check 2: Not a soft-404
        if self.is_soft_404(body, status):
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "Soft-404 match"}

        # Check 3: Not HTML masquerading as a file
        if self.is_html_masquerading(ct, body, expected_type):
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "reason": "HTML response for non-HTML resource"}

        # Check 4: Content pattern validation
        if content_patterns:
            matches = sum(1 for p in content_patterns if p in body)
            if matches == 0:
                return {"valid": False, "confidence": "LOW", "confidence_score": 10, "reason": "No expected content patterns found"}
            confidence_score = min(95, 50 + (matches * 15))
            return {
                "valid": True,
                "confidence": "CONFIRMED" if confidence_score >= 95 else "HIGH" if confidence_score >= 75 else "MEDIUM",
                "confidence_score": confidence_score,
                "reason": f"Matched {matches}/{len(content_patterns)} content patterns",
            }

        # Check 5: Body must have non-trivial content
        if len(body.strip()) < 10:
            return {"valid": False, "confidence": "LOW", "confidence_score": 5, "reason": "Empty or trivial response"}

        return {
            "valid": True,
            "confidence": "MEDIUM",
            "confidence_score": 60,
            "reason": "200 OK with non-HTML content, no soft-404 match",
        }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 2: Differential Confirmation
    # ═══════════════════════════════════════════════════════════════════════════

    def differential_test(
        self,
        url: str,
        param: str,
        true_payload: str,
        false_payload: str,
        baseline_value: str = "",
        timeout: int = 10,
        send_fn=None,
    ) -> dict:
        """
        Three-probe differential test for boolean-based injection.

        1. Send true_payload → should match baseline behavior
        2. Send false_payload → should differ from baseline
        3. Send baseline_value again → should recover to baseline (control)

        Args:
            send_fn: optional callable(value: str) -> response. When given,
                it is used to deliver each probe value instead of the default
                GET-query-string injection — lets callers drive the same
                true/false/control logic through POST bodies, JSON, XML,
                headers, or path segments.

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "details": str}
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        def inject_param(target_url: str, p: str, value: str) -> str:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[p] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        if send_fn:
            probe = lambda value: send_fn(value)
        else:
            probe = lambda value: self._get(inject_param(url, param, value), timeout=timeout)

        # Baseline request. NOTE: requests.Response is falsy for ANY non-2xx
        # status (bool(resp) == resp.ok) — a 401/403/500 response is a
        # perfectly valid, meaningful probe result (often exactly where the
        # interesting behavior is), so every check here must be `is None`,
        # never plain truthiness, or auth-walled/error-returning endpoints
        # get silently treated as "request failed" and skipped entirely.
        baseline_resp = probe(baseline_value)
        if baseline_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "Baseline request failed"}

        baseline_hash = self._structural_hash(baseline_resp.text)
        baseline_len = len(baseline_resp.text)

        # True probe
        true_resp = probe(true_payload)
        if true_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "True probe failed"}

        true_hash = self._structural_hash(true_resp.text)
        true_len = len(true_resp.text)

        # False probe
        false_resp = probe(false_payload)
        if false_resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "details": "False probe failed"}

        false_hash = self._structural_hash(false_resp.text)
        false_len = len(false_resp.text)

        # Control probe (repeat baseline)
        control_resp = probe(baseline_value)
        control_hash = self._structural_hash(control_resp.text) if control_resp is not None else ""

        # Analysis. We do NOT assume the baseline_value represents the "true"
        # condition — that only holds for classic `?id=1` style params. For
        # something like a login endpoint, the baseline is deliberately
        # invalid credentials (a FALSE condition), so a true auth-bypass
        # payload is the one that DIFFERS from baseline, and the false payload
        # is the one that matches it (still rejected, same as baseline). Both
        # orientations are checked — only the divergence between true/false,
        # and one of them anchoring to the known-stable baseline, matters.
        def _matches_baseline(h, l):
            return (h == baseline_hash) or (abs(l - baseline_len) < max(50, baseline_len * 0.03))

        true_matches_baseline  = _matches_baseline(true_hash, true_len)
        false_matches_baseline = _matches_baseline(false_hash, false_len)
        true_differs  = not true_matches_baseline
        false_differs = not false_matches_baseline
        # Control should match baseline (proves no jitter)
        control_matches = control_hash == baseline_hash if control_hash else False

        # Orientation A: baseline == true state (e.g. ?id=1)
        orientation_a = true_matches_baseline and false_differs
        # Orientation B: baseline == false state (e.g. invalid login creds)
        orientation_b = false_matches_baseline and true_differs
        orientation = "true≈baseline, false diverges" if orientation_a else "false≈baseline, true diverges"

        if (orientation_a or orientation_b) and control_matches:
            return {
                "valid": True,
                "confidence": "CONFIRMED",
                "confidence_score": 95,
                "details": f"Differential confirmed ({orientation}): true={true_len}b, false={false_len}b, "
                           f"baseline={baseline_len}b, control recovered",
            }
        elif orientation_a or orientation_b:
            return {
                "valid": True,
                "confidence": "HIGH",
                "confidence_score": 80,
                "details": f"Differential likely ({orientation}): true/false diverge but control probe inconclusive",
            }
        else:
            return {
                "valid": False,
                "confidence": "LOW",
                "confidence_score": 15,
                "details": f"No differential: responses don't follow boolean logic pattern",
            }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 3: Statistical Timing Verification
    # ═══════════════════════════════════════════════════════════════════════════

    def validate_time_based(
        self,
        url: str,
        param: str,
        delay_payload: str,
        expected_delay: float = 5.0,
        baseline_value: str = "",
        timeout: int = 15,
        z_threshold: float = 3.5,
        send_fn=None,
    ) -> dict:
        """
        Statistical timing verification for time-based blind injection.

        1. Measure 5 baseline response times → compute μ, σ
        2. Send delay payload → measure response time
        3. Compute Z-score: Z = (T_payload - μ) / σ
        4. Send control probe → must return to baseline
        5. Require Z ≥ z_threshold AND control recovery

        Args:
            send_fn: optional callable(value: str, timeout: float) -> response.
                When given, used to deliver every probe instead of the default
                GET-query-string injection (see differential_test).

        Returns:
            {"valid": bool, "confidence": str, "confidence_score": int, "z_score": float, "details": str}
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        def inject_param(target_url: str, p: str, value: str) -> str:
            parsed = urlparse(target_url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[p] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))

        if send_fn:
            probe = lambda value, t: send_fn(value, t)
        else:
            probe = lambda value, t: self._get(inject_param(url, param, value), timeout=t)

        # Use stored baseline if available, otherwise measure
        if self.baseline and self.baseline.baseline_mean > 0:
            mu = self.baseline.baseline_mean
            sigma = self.baseline.baseline_stdev
        else:
            # Measure baseline
            times = []
            for _ in range(5):
                start = time.time()
                resp = probe(baseline_value, timeout)
                elapsed = time.time() - start
                if resp is not None:
                    times.append(elapsed)

            if len(times) < 3:
                return {"valid": False, "confidence": "LOW", "confidence_score": 0, "z_score": 0, "details": "Insufficient baseline measurements"}

            mu = statistics.mean(times)
            sigma = statistics.stdev(times) if len(times) > 1 else 0.1

        # Avoid division by near-zero sigma
        if sigma < 0.05:
            sigma = 0.05

        # Send delay payload
        start = time.time()
        resp = probe(delay_payload, timeout + expected_delay + 5)
        payload_time = time.time() - start

        if resp is None:
            return {"valid": False, "confidence": "LOW", "confidence_score": 0, "z_score": 0, "details": "Payload request failed or timed out"}

        # Calculate Z-score
        z_score = (payload_time - mu) / sigma

        # Control probe — must return to baseline
        start = time.time()
        control_resp = probe(baseline_value, timeout)
        control_time = time.time() - start

        control_z = (control_time - mu) / sigma if control_resp is not None else 999

        # Verdict
        payload_delayed = z_score >= z_threshold and payload_time >= (mu + expected_delay * 0.7)
        control_normal = control_z < 2.0  # Control should be within 2σ of baseline

        if payload_delayed and control_normal:
            return {
                "valid": True,
                "confidence": "CONFIRMED",
                "confidence_score": 95,
                "z_score": z_score,
                "details": f"Time-based confirmed: payload={payload_time:.2f}s (Z={z_score:.1f}), control={control_time:.2f}s (normal), μ={mu:.2f}s σ={sigma:.2f}s",
            }
        elif payload_delayed:
            return {
                "valid": True,
                "confidence": "HIGH",
                "confidence_score": 75,
                "z_score": z_score,
                "details": f"Payload delayed (Z={z_score:.1f}) but control also slow ({control_time:.2f}s) — possible network jitter",
            }
        else:
            return {
                "valid": False,
                "confidence": "LOW",
                "confidence_score": 10,
                "z_score": z_score,
                "details": f"No significant delay: payload={payload_time:.2f}s, Z={z_score:.1f} < {z_threshold}",
            }

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 4: Reflection & Context Validation
    # ═══════════════════════════════════════════════════════════════════════════

    def validate_reflection(
        self,
        body: str,
        payload: str,
        context: str = "any",
    ) -> dict:
        """
        Validate that a reflected payload is actually exploitable in its DOM context.

        Args:
            body: Response HTML body
            payload: The injected payload string
            context: Expected context — "html_body", "html_attr", "js_context", "any"

        Returns:
            {"exploitable": bool, "context": str, "confidence": str, "confidence_score": int, "reason": str}
        """
        if payload not in body:
            return {"exploitable": False, "context": "none", "confidence": "LOW", "confidence_score": 0, "reason": "Payload not reflected"}

        # Check if payload is HTML-entity encoded (safe)
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in body and payload not in body.replace(encoded_payload, ""):
            return {"exploitable": False, "context": "encoded", "confidence": "LOW", "confidence_score": 5, "reason": "Payload is HTML-entity encoded"}

        # Try to determine the DOM context of the reflection
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(body, "html.parser")

            # Check if it's inside a <script> tag
            for script in soup.find_all("script"):
                if script.string and payload in script.string:
                    return {"exploitable": True, "context": "js_context", "confidence": "HIGH", "confidence_score": 85, "reason": "Payload reflected inside <script> tag"}

            # Check if it's inside an HTML attribute
            for tag in soup.find_all(True):
                for attr, val in (tag.attrs or {}).items():
                    val_str = str(val)
                    if payload in val_str:
                        # Check if it can break out of the attribute
                        if '"' in payload or "'" in payload:
                            return {"exploitable": True, "context": "html_attr_breakout", "confidence": "HIGH", "confidence_score": 85, "reason": "Payload in attribute with quote breakout"}
                        else:
                            return {"exploitable": False, "context": "html_attr_contained", "confidence": "LOW", "confidence_score": 20, "reason": "Payload in attribute but contained by quotes"}

            # Check if it's inside an HTML comment
            comments = body.count("<!--")
            for comment_start in [m.start() for m in re.finditer(r'<!--', body)]:
                comment_end = body.find("-->", comment_start)
                if comment_end > comment_start:
                    comment_body = body[comment_start:comment_end]
                    if payload in comment_body:
                        if "-->" in payload:
                            return {"exploitable": True, "context": "html_comment_breakout", "confidence": "HIGH", "confidence_score": 80, "reason": "Payload in comment with breakout"}
                        return {"exploitable": False, "context": "html_comment", "confidence": "LOW", "confidence_score": 10, "reason": "Payload trapped inside HTML comment"}

            # It's in the HTML body — check for unencoded dangerous tags
            dangerous_patterns = [
                r'<script[^>]*>', r'<img[^>]*onerror', r'<svg[^>]*onload',
                r'<iframe[^>]*>', r'<body[^>]*onload', r'javascript:',
                r'<input[^>]*onfocus', r'<details[^>]*ontoggle',
            ]
            for pattern in dangerous_patterns:
                if re.search(pattern, body[max(0, body.index(payload) - 50):body.index(payload) + len(payload) + 50], re.IGNORECASE):
                    return {"exploitable": True, "context": "html_body", "confidence": "CONFIRMED", "confidence_score": 95, "reason": f"Unencoded dangerous tag/handler near payload"}

        except Exception:
            pass  # BeautifulSoup not available or parse error

        # Fallback: basic check
        if "<" in payload and ">" in payload and payload in body:
            return {"exploitable": True, "context": "html_body", "confidence": "MEDIUM", "confidence_score": 60, "reason": "Unencoded angle brackets reflected (basic check)"}

        return {"exploitable": False, "context": "unknown", "confidence": "LOW", "confidence_score": 25, "reason": "Payload reflected but context unclear"}

    # ═══════════════════════════════════════════════════════════════════════════
    # STAGE 5: AI Semantic Verification
    # ═══════════════════════════════════════════════════════════════════════════

    def ai_verify(
        self,
        finding_type: str,
        url: str,
        baseline_response: str,
        payload_response: str,
        payload: str,
        extra_context: str = "",
    ) -> dict:
        """
        Use NVIDIA NIM AI to semantically evaluate whether a finding is genuine.

        Returns:
            {"is_vulnerable": bool, "confidence": float, "reasoning": str}
        """
        if not self.ai or not self.ai.enabled:
            return {"is_vulnerable": True, "confidence": 0.5, "reasoning": "AI unavailable — manual review recommended"}

        system = (
            "You are a senior penetration tester reviewing automated scanner output. "
            "Your job is to determine if a finding is a TRUE vulnerability or a FALSE POSITIVE. "
            "Consider: SPA routing, public data, generic error pages, CDN caching, parameter reflection "
            "without execution, and other common false positive causes. "
            "Respond with ONLY valid JSON: "
            '{"is_vulnerable": true/false, "confidence": 0.0-1.0, "reasoning": "one sentence"}'
        )

        user = (
            f"Finding type: {finding_type}\n"
            f"URL: {url}\n"
            f"Payload: {payload}\n"
            f"Baseline response (first 500 chars):\n{baseline_response[:500]}\n\n"
            f"Payload response (first 500 chars):\n{payload_response[:500]}\n\n"
            f"{extra_context}\n\n"
            "Is this a genuine vulnerability or a false positive?"
        )

        result = self.ai._call(system, user, max_tokens=200)
        if result:
            try:
                import json
                start = result.find("{")
                end = result.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(result[start:end])
            except Exception:
                pass

        return {"is_vulnerable": True, "confidence": 0.5, "reasoning": "AI response parse failed — flagging for manual review"}

    # ═══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _structural_hash(self, body: str) -> str:
        """
        Hash of the response's structure for differential comparison.
        JSON bodies (the norm for REST APIs) are hashed by key-path shape,
        not raw HTML-tag sequence — the tag regex finds nothing in a JSON
        body, which previously made every JSON response hash identically
        (MD5 of an empty string) and silently turned the structural-equality
        check in differential_test()/validate_time_based() into a no-op for
        any JSON API. Falls back to HTML tag-sequence hashing otherwise.
        """
        stripped = body.strip()
        if stripped[:1] in ("{", "["):
            try:
                data = json.loads(stripped)
                paths = sorted(_json_shape_paths(data))
                return hashlib.md5("|".join(paths).encode()).hexdigest()
            except Exception:
                pass

        tags = re.findall(r'</?[a-zA-Z][a-zA-Z0-9]*[^>]*>', body)
        normalized = []
        for tag in tags[:200]:
            match = re.match(r'</?([a-zA-Z][a-zA-Z0-9]*)', tag)
            if match:
                normalized.append(match.group(0).lower())
        structure = "|".join(normalized)
        return hashlib.md5(structure.encode()).hexdigest()

    @staticmethod
    def compute_confidence(
        checks_passed: int,
        checks_total: int,
        verification_type: str = "heuristic",
    ) -> tuple[str, int]:
        """
        Compute confidence label and score from validation results.

        Args:
            checks_passed: Number of validation checks that passed
            checks_total: Total validation checks performed
            verification_type: "confirmed" (OAST/exec), "differential", "heuristic", "static"

        Returns:
            (confidence_label, confidence_score)
        """
        if checks_total == 0:
            return ("LOW", 25)

        ratio = checks_passed / checks_total

        # Type multiplier
        multipliers = {
            "confirmed": 1.0,      # OAST callback, code execution
            "differential": 0.9,   # Boolean/timing differential
            "heuristic": 0.7,      # Pattern matching with validation
            "static": 0.5,         # Static analysis only
        }
        mult = multipliers.get(verification_type, 0.7)

        score = int(ratio * 100 * mult)
        score = max(5, min(100, score))

        if score >= 95:
            return ("CONFIRMED", score)
        elif score >= 75:
            return ("HIGH", score)
        elif score >= 50:
            return ("MEDIUM", score)
        else:
            return ("LOW", score)

    def validate_cookie_is_session(self, cookie_name: str) -> bool:
        """
        Check if a cookie name is likely a session cookie (vs analytics/tracking).
        Used to fix false positives in headers.py.
        """
        session_indicators = [
            "session", "sess", "sid", "token", "auth", "jwt",
            "csrf", "xsrf", "login", "user", "identity",
            "phpsessid", "jsessionid", "asp.net_sessionid",
            "connect.sid", "laravel_session", "ci_session",
        ]
        tracking_cookies = [
            "_ga", "_gid", "_gat", "_fbp", "_fbc", "_gcl",
            "__utma", "__utmb", "__utmc", "__utmz",
            "_hjid", "_hjFirstSeen", "mp_", "ajs_",
            "intercom-", "hubspot", "optimizely", "vwo_",
        ]

        name_lower = cookie_name.lower()

        # Known tracking cookies
        for tracker in tracking_cookies:
            if name_lower.startswith(tracker) or name_lower == tracker:
                return False

        # Known session indicators
        for indicator in session_indicators:
            if indicator in name_lower:
                return True

        # If not clearly tracking and not clearly session, treat as unknown
        return False

    def validate_ssrf_indicator(self, indicator: str, payload_url: str, response_body: str) -> bool:
        """
        Validate an SSRF indicator isn't just the payload URL being reflected.
        Fixes the critical bug where ssrf.py matched its own injected URL string.
        """
        # If the indicator string is a substring of the payload URL itself,
        # we need to check it's not just reflection
        if indicator.lower() in payload_url.lower():
            # The indicator is part of the payload — check if it appears
            # OUTSIDE the reflected payload URL in the response
            # Remove all occurrences of the payload URL from the body
            cleaned = response_body.replace(payload_url, "")
            return indicator in cleaned

        # Indicator is not in the payload — safe to check directly
        return indicator in response_body
