"""
GhostRecon modules package.
BaseModule is the shared base class for all scan modules.
"""

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

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

    def _session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 GhostRecon/3.0"})
        s.verify = False
        return s

    def _get(self, url, params=None):
        try:
            s = self._session()
            return s.get(url, params=params, timeout=self.timeout)
        except Exception:
            return None


# ─── Headers Module ───────────────────────────────────────────────────────────