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


# ─── Headers Module ───────────────────────────────────────────────────────────