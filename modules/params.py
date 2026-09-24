"""
ParamModule — GhostRecon module.

Parameter tampering: numeric boundary values (negative/zero/overflow) and
boolean/privilege-flag flips (admin=0 -> admin=1, etc.), validated against a
baseline + control-recovery check so a genuine, stable behavior change is
required before anything is flagged — not just "the response looked
different" (which is noisy on any page with dynamic content).
"""
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


PRIVILEGE_PARAM_NAMES = {
    "admin", "is_admin", "isadmin", "administrator", "debug", "test",
    "bypass", "verified", "is_verified", "premium", "role", "access",
    "authenticated", "is_authenticated", "superuser", "root", "privileged",
}

BOOLEAN_FLIPS = {
    "0": "1", "1": "0",
    "false": "true", "true": "false",
    "no": "yes", "yes": "no",
    "n": "y", "y": "n",
}


class ParamModule(BaseModule):
    NAME = "Parameter Tampering"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = self._session()

    def run(self):
        self.ui.section("Parameter Tampering")
        if not requests:
            return

        endpoints = self.ctx.get("endpoints", [self.base_url])
        params_found = []
        for ep in endpoints:
            parsed = urllib.parse.urlparse(ep)
            if not parsed.query:
                continue
            base_url = parsed.scheme + "://" + parsed.netloc + parsed.path
            qs = urllib.parse.parse_qs(parsed.query)
            for k, v in qs.items():
                params_found.append((base_url, k, v[0] if v else "", qs))

        self.ui.info(f"Parameters in scope: {len(params_found)} from {len(endpoints)} endpoints")
        # Preserve the (endpoint, param) tuple shape other code already reads.
        self.ctx["discovered_params"] = [(ep, k) for ep, k, _, _ in params_found]

        found = 0
        tested = 0
        for base_url, param, value, qs in params_found[:60]:  # cap for scan time
            other = {k: v[0] for k, v in qs.items() if k != param and v}
            candidates = self._build_candidates(param, value)
            if not candidates:
                continue
            tested += 1
            try:
                if self._test_param(base_url, param, value, other, candidates):
                    found += 1
            except Exception:
                continue
            time.sleep(self.delay)

        self.ui.info(f"Tested {tested} parameter(s) for tampering")
        if found == 0:
            self.ui.info("No parameter tampering issues detected.")

    def _build_candidates(self, param, value):
        candidates = []
        if value.isdigit():
            n = int(value)
            candidates.append(str(-n) if n else "-1")
            candidates.append("0")
            candidates.append(str(n * 1000 + 99999))
        if value.lower() in BOOLEAN_FLIPS:
            candidates.append(BOOLEAN_FLIPS[value.lower()])
        if param.lower() in PRIVILEGE_PARAM_NAMES:
            candidates += ["1", "true", "admin", "yes"]

        seen = set()
        out = []
        for c in candidates:
            if c != value and c not in seen:
                seen.add(c)
                out.append(c)
        return out

    def _test_param(self, url, param, orig_value, other, candidates):
        baseline_resp = self._send(url, param, orig_value, other)
        if baseline_resp is None:
            return False
        baseline_len = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code

        for candidate in candidates:
            resp = self._send(url, param, candidate, other)
            if resp is None:
                continue

            len_diff = abs(len(resp.text) - baseline_len)
            significant = len_diff > max(80, baseline_len * 0.05)
            status_improved = (
                baseline_status in (401, 403, 404) and resp.status_code == 200
            )
            if not (significant or status_improved):
                continue

            # Confirm this isn't just generic response jitter: re-send the
            # original value and require it to still match the baseline.
            control = self._send(url, param, orig_value, other)
            if control is None or abs(len(control.text) - baseline_len) > max(80, baseline_len * 0.05):
                continue

            title = f"Parameter Tampering: '{param}' accepts unexpected value"
            desc = (
                f"Changing '{param}' from '{orig_value}' to '{candidate}' produced a materially "
                f"different, stable response (baseline {baseline_len}b/{baseline_status} vs "
                f"{len(resp.text)}b/{resp.status_code}), suggesting the value is not properly "
                f"authorized or validated server-side."
            )
            added = self.db.add(
                title=title, severity="medium", url=url, module=self.NAME,
                description=desc,
                remediation="Enforce server-side authorization and validation for this parameter; "
                            "never trust client-supplied values for privilege or business-logic decisions.",
                cvss="6.5",
                confidence="MEDIUM", confidence_score=60,
                validation_steps=["baseline_captured", "candidate_diverged", "control_stable"],
                evidence=[
                    f"Original: {param}={orig_value}", f"Tampered: {param}={candidate}",
                    f"Baseline: {baseline_len}b/{baseline_status}",
                    f"Tampered response: {len(resp.text)}b/{resp.status_code}",
                ],
            )
            if added:
                self.ui.find("medium", title, url)
                self.ui.bullet(f"{param}: {orig_value} -> {candidate}", indent=12)
                return True
        return False

    def _send(self, url, param, value, other):
        try:
            params = {**other, param: value}
            return self.session.get(url, params=params, timeout=self.timeout, allow_redirects=True)
        except RequestException:
            return None
