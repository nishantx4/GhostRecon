"""
ReconModule — crawls target, extracts endpoints, parameters, and forms.
Feeds XSS, SQLi, and other modules with real data.
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


from modules import BaseModule


class ReconModule(BaseModule):
    NAME = "Recon"

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
        self.session    = self._make_session()
        self.visited    = set()
        self.endpoints  = set()
        self.forms      = []

    def _make_session(self):
        if not requests:
            return None
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        })
        s.verify = False
        s.max_redirects = 5
        return s

    def _resolve_base_url(self):
        """Try HTTPS first, fall back to HTTP if it fails."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{self.target}"
            try:
                r = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code < 500:
                    # Follow any redirect to get the real base
                    return r.url.rstrip("/").split("?")[0]
            except Exception:
                continue
        return f"http://{self.target}"

    def run(self):
        self.ui.section("Recon — Crawling & Endpoint Discovery")
        if not requests:
            self.ui.error("requests not installed.")
            return

        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

        # Resolve real base URL (HTTP vs HTTPS auto-detect)
        self.ui.info(f"Resolving base URL for {self.target} ...")
        self.base_url = self._resolve_base_url()
        self.ctx["base_url"] = self.base_url   # ← share with other modules
        self.ui.ok(f"Base URL resolved: {self.base_url}")

        # Start crawl
        self.ui.info(f"Crawling {self.base_url} ...")
        self._crawl(self.base_url, depth=2)

        # Always seed endpoints with known-injectable probe paths
        # so XSS/SQLi have targets even if the crawl fails
        self._probe_common_paths()

        # Update context
        ep_list = list(self.endpoints)
        self.ctx["endpoints"] = ep_list
        self.ctx["forms"]     = self.forms
        self.ctx.setdefault("subdomains", [self.target])

        # ── AI: prioritize endpoints for deeper testing ───────────────
        if self.ai and self.ai.enabled and ep_list:
            ep_list = self.ai.prioritize_endpoints(ep_list)
            self.ctx["ai_priority_endpoints"] = ep_list[:20]
            self.ui.subsection("AI Top-Priority Endpoints")
            for ep in ep_list[:10]:
                self.ui.bullet(ep)
            self.ui.blank()

        self.ui.ok(f"Recon complete — {len(ep_list)} endpoints, {len(self.forms)} forms discovered")

    def _crawl(self, url, depth=2):
        if depth == 0 or url in self.visited:
            return
        self.visited.add(url)
        # Add to endpoints immediately — even if the request fails we
        # know this URL exists (we resolved it in _resolve_base_url).
        self.endpoints.add(url)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            time.sleep(self.delay)
        except Exception:
            return

        # Extract links and forms
        links = self._extract_links(resp.text, url)
        self._extract_forms(resp.text, url)

        # Recurse into same-domain links
        for link in links:
            if self._same_domain(link) and link not in self.visited:
                self.endpoints.add(link)
                if depth > 1:
                    self._crawl(link, depth - 1)

    def _extract_links(self, html, base_url):
        links = set()
        # href and src attributes
        for match in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.I):
            raw = match.group(1).strip()
            if raw.startswith(("javascript:", "mailto:", "#", "data:")):
                continue
            try:
                full = urllib.parse.urljoin(base_url, raw)
                links.add(full)
            except Exception:
                pass
        return links

    def _extract_forms(self, html, page_url):
        # Find all <form> elements
        for form_match in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.I | re.S):
            form_html = form_match.group(0)
            action_m  = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
            method_m  = re.search(r'method\s*=\s*["\']([^"\']*)["\']', form_html, re.I)

            action = urllib.parse.urljoin(page_url, action_m.group(1)) if action_m else page_url
            method = method_m.group(1).upper() if method_m else "GET"

            inputs = {}
            for inp in re.finditer(r'<input[^>]+>', form_html, re.I):
                inp_html = inp.group(0)
                name_m  = re.search(r'name\s*=\s*["\']([^"\']+)["\']', inp_html, re.I)
                val_m   = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp_html, re.I)
                type_m  = re.search(r'type\s*=\s*["\']([^"\']+)["\']', inp_html, re.I)
                if name_m:
                    inp_type = type_m.group(1).lower() if type_m else "text"
                    if inp_type not in ("submit", "button", "image", "reset", "file"):
                        inputs[name_m.group(1)] = val_m.group(1) if val_m else ""

            # Also pick up <textarea> and <select> names
            for ta in re.finditer(r'<textarea[^>]*name\s*=\s*["\']([^"\']+)["\']', form_html, re.I):
                inputs[ta.group(1)] = ""
            for sel in re.finditer(r'<select[^>]*name\s*=\s*["\']([^"\']+)["\']', form_html, re.I):
                inputs[sel.group(1)] = ""

            if inputs:
                self.forms.append({"action": action, "method": method, "inputs": inputs})
                self.endpoints.add(action)

    def _probe_common_paths(self):
        """
        Probe well-known injectable paths.
        ALL paths are added to ctx['probe_targets'] so XSS/SQLi can
        test them regardless of whether they respond.
        Paths that actually return a live response are also added to
        self.endpoints.
        """
        paths = [
            # Generic search / input params
            "/search.php?test=query",
            "/search?q=test",
            "/?s=test",
            "/?q=test",
            # ID-based pages (prime SQLi targets)
            "/index.php?id=1",
            "/page.php?id=1",
            "/item.php?id=1",
            "/view.php?id=1",
            "/show.php?id=1",
            "/detail.php?id=1",
            "/news.php?id=1",
            "/product.php?id=1",
            # vulnweb / acunetix style (deliberately vulnerable)
            "/listproducts.php?cat=1",
            "/artists.php?artist=1",
            "/userinfo.php?uid=1",
            "/guestbook.php",
            "/comment.php",
            "/showimage.php?file=1",
            "/hpp/params.php?p=1&pp=2",
            "/Mod_Rewrite_Shop/",
            "/AJAX/index.php",
            "/signup.php",
            # Auth / common
            "/login.php",
            "/login",
            "/register",
            "/contact.php",
            # Admin
            "/admin",
            "/admin.php",
            # API
            "/api/v1/search",
            "/api/search",
            "/api/users",
        ]
        probe_targets = []
        for path in paths:
            url = urllib.parse.urljoin(self.base_url, path)
            probe_targets.append(url)
            # Add immediately so scanners always have these targets
            self.endpoints.add(url)

        # Store probe targets in context for XSS/SQLi to use directly
        self.ctx["probe_targets"] = probe_targets

        self.ui.info(f"Probing {len(paths)} common paths for live responses...")
        probe_timeout = min(self.timeout, 8)  # shorter timeout for probing
        for url in probe_targets:
            try:
                resp = self.session.get(url, timeout=probe_timeout, allow_redirects=True)
                if resp.status_code not in (404, 410):
                    self._extract_forms(resp.text, url)
                    if self.verbose:
                        self.ui.info(f"  [{resp.status_code}] {url}")
                time.sleep(self.delay * 0.5)  # half delay for probing
            except Exception:
                pass

    def _same_domain(self, url):
        try:
            parsed = urllib.parse.urlparse(url)
            return self.target in parsed.netloc
        except Exception:
            return False
