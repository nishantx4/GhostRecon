"""
GhostRecon modules package.
BaseModule is the shared base class for all scan modules.
"""

import time
import threading

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None


# Process-wide throttle so concurrent modules/threads honour --delay and don't
# hammer a target. Spreads requests by at least `delay` seconds globally.
_RATE_LOCK = threading.Lock()
_LAST_REQUEST = [0.0]

# Field names that plausibly hold a live session/API token in a JSON response.
_TOKEN_FIELD_NAMES = {
    "token", "access_token", "accesstoken", "jwt", "id_token",
    "session_id", "sessionid", "session_token", "api_key", "apikey",
    "auth_token", "bearer", "authtoken",
}


_TOKEN_LEAF_KEYS = {"id", "value", "key", "code", "hash", "secret", "string"}


def _looks_like_token_value(s: str) -> bool:
    """Reject obviously-non-token strings (dates, sentences) that would
    otherwise be the first string a naive walk stumbles onto — a token/id
    value never contains whitespace."""
    return len(s) >= 8 and " " not in s


def _first_string_leaf(data, depth=0, max_depth=3):
    """Find the first plausible string value nested inside a token-shaped
    subtree, e.g. {"token": {"id": "86462f8c...", "expires": "Thu Sep..."}}
    — the key that matched ("token") isn't itself a string, and the real
    value is one level deeper under a generic name ("id") that isn't
    independently recognizable as token-like anywhere else in a JSON body.
    Prefers identifier-shaped keys and rejects date/sentence-shaped values
    (containing whitespace) so a sibling "expires" timestamp doesn't win
    over the actual token just by appearing first in the dict."""
    if depth > max_depth:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, str) and isinstance(k, str) and k.lower() in _TOKEN_LEAF_KEYS and _looks_like_token_value(v):
                return k, v
        for k, v in data.items():
            if isinstance(v, str) and _looks_like_token_value(v):
                return k, v
        for v in data.values():
            found = _first_string_leaf(v, depth + 1, max_depth)
            if found:
                return found
    elif isinstance(data, list) and data:
        return _first_string_leaf(data[0], depth + 1, max_depth)
    return None


def _find_token_in_json(data, depth=0):
    """Recursively search a decoded JSON body for a plausible token field.
    Returns (key, value) or None."""
    if depth > 4:
        return None
    if isinstance(data, dict):
        for k, v in data.items():
            if not isinstance(k, str) or k.lower() not in _TOKEN_FIELD_NAMES:
                continue
            if isinstance(v, str) and _looks_like_token_value(v):
                return k, v
            if isinstance(v, (dict, list)):
                nested = _first_string_leaf(v)
                if nested:
                    return f"{k}.{nested[0]}", nested[1]
        for v in data.values():
            found = _find_token_in_json(v, depth + 1)
            if found:
                return found
    elif isinstance(data, list):
        for item in data[:20]:
            found = _find_token_in_json(item, depth + 1)
            if found:
                return found
    return None


class BaseModule:
    NAME = "Base"

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
        self.base_url   = f"https://{target}" if not target.startswith("http") else target
        
        # Instantiate common tools
        try:
            from core.validator import Validator
            self.validator = Validator()
        except ImportError:
            self.validator = None
            
        try:
            from core.tool_runner import ExternalToolRunner
            self.tool_runner = ExternalToolRunner(self.ui)
        except ImportError:
            self.tool_runner = None

    def _throttle(self):
        """Global rate limiter: ensure at least `delay` between any two requests."""
        if self.delay <= 0:
            return
        with _RATE_LOCK:
            wait = self._next_allowed() - time.time()
            if wait > 0:
                time.sleep(wait)
            _LAST_REQUEST[0] = time.time()

    def _next_allowed(self):
        return _LAST_REQUEST[0] + self.delay

    def _session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 GhostRecon/3.0"})
        s.verify = False
        return s

    def _get(self, url, params=None):
        try:
            self._throttle()
            s = self._session()
            return s.get(url, params=params, timeout=self.timeout)
        except Exception:
            return None

    # ── Live credential propagation ─────────────────────────────────────────
    # Most scanners test every endpoint unauthenticated in isolation. Here,
    # any module that stumbles onto a real working credential (an auth-bypass
    # SQLi that returns a live token, a forged JWT that gets accepted, a
    # cracked login) can register it so every module that runs afterward
    # automatically attaches it — turning a set of isolated blind probes into
    # a stateful, authenticated deep scan of the target.
    def capture_credential(self, kind: str, value, source: str = ""):
        """
        Register a live credential discovered during the scan.
        kind: 'header' (value is a {name: value} dict), 'cookie' (value is a
        {name: value} dict), or 'bearer' (value is a raw token string, sent
        as an Authorization: Bearer header).
        """
        store = self.ctx.setdefault("captured_credentials", [])
        store.append({"kind": kind, "value": value, "source": source, "module": self.NAME})

        if kind == "header" and isinstance(value, dict):
            self.ctx.setdefault("auth_headers", {}).update(value)
        elif kind == "cookie" and isinstance(value, dict):
            self.ctx.setdefault("auth_cookies", {}).update(value)
        elif kind == "bearer" and isinstance(value, str):
            self.ctx.setdefault("auth_headers", {})["Authorization"] = f"Bearer {value}"

        if self.ui:
            self.ui.warn(
                f"Captured live credential ({kind}) from {source or self.NAME} "
                f"— propagating to remaining modules"
            )

    def auth_headers(self) -> dict:
        """Headers to attach to authenticated probes: OpenAPI-derived example
        headers merged with any live credential captured so far this scan."""
        return dict(self.ctx.get("auth_headers", {}))

    def auth_cookies(self) -> dict:
        return dict(self.ctx.get("auth_cookies", {}))

    def try_capture_credential_from_response(self, resp, source: str = ""):
        """
        Heuristic scan of a response for a live token/session worth reusing.
        Safe to call on any response — a no-op unless something token-shaped
        is actually present. Looks at JSON body fields (token/access_token/
        jwt/session_id/api_key/...) and Set-Cookie headers for a
        session-shaped cookie name.
        """
        if resp is None or not hasattr(resp, "headers"):
            return

        try:
            ct = resp.headers.get("Content-Type", "")
            if "json" in ct.lower():
                import json as _json
                data = _json.loads(resp.text)
                found = _find_token_in_json(data)
                if found:
                    key, val = found
                    self.capture_credential("bearer", val, source=f"{source} (field '{key}')")
        except Exception:
            pass

        try:
            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie and self.validator:
                cookie_kv = set_cookie.split(";", 1)[0]
                cname, _, cval = cookie_kv.partition("=")
                cname = cname.strip()
                if cname and self.validator.validate_cookie_is_session(cname):
                    self.capture_credential("cookie", {cname: cval.strip()}, source=source)
        except Exception:
            pass


# ─── Headers Module ───────────────────────────────────────────────────────────