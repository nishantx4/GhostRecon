"""
Baseline Profiler — Pre-scan target fingerprinting for false positive elimination.

Runs before any scan module to establish:
  - Soft-404 detection (custom error pages returning HTTP 200)
  - Response jitter measurement (μ, σ for timing-based checks)
  - WAF detection (Cloudflare, Akamai, Imperva, etc.)
  - Technology fingerprinting (server, framework, CMS)
  - SPA detection (React/Vue/Angular single-page apps)
"""

import re
import time
import uuid
import statistics
import hashlib
from dataclasses import dataclass, field
from typing import Any

try:
    import requests as _requests
    from requests.exceptions import RequestException
except ImportError:
    _requests = None


@dataclass
class BaselineProfile:
    """Complete baseline fingerprint of a target."""
    target: str = ""
    base_url: str = ""

    # Soft-404 detection
    soft_404_detected: bool = False
    soft_404_fingerprint: str = ""    # structural hash of custom error page
    soft_404_content_length: int = 0
    soft_404_signatures: list[str] = field(default_factory=list)  # text patterns

    # Response timing
    baseline_mean: float = 0.0        # μ — mean response time
    baseline_stdev: float = 0.0       # σ — standard deviation
    baseline_times: list[float] = field(default_factory=list)

    # WAF detection
    waf_detected: bool = False
    waf_name: str = ""
    waf_headers: dict[str, str] = field(default_factory=dict)

    # Technology
    server: str = ""
    technologies: list[str] = field(default_factory=list)
    cms: str = ""                      # wordpress, joomla, drupal, etc.
    is_spa: bool = False               # React/Vue/Angular

    # Default response fingerprint
    default_status: int = 0
    default_content_length: int = 0
    default_content_type: str = ""
    default_structural_hash: str = ""  # hash of HTML tag structure

    def time_is_anomalous(self, response_time: float, z_threshold: float = 3.5) -> bool:
        """Check if a response time is statistically anomalous (for time-based blind testing)."""
        if self.baseline_stdev == 0 or self.baseline_mean == 0:
            return False
        z_score = (response_time - self.baseline_mean) / self.baseline_stdev
        return z_score >= z_threshold

    def matches_soft_404(self, body: str, status: int = 200) -> bool:
        """Check if a response matches the soft-404 fingerprint."""
        if not self.soft_404_detected:
            return False
        if status != 200:
            return False

        # Check structural hash match
        body_hash = _structural_hash(body)
        if body_hash == self.soft_404_fingerprint:
            return True

        # Check signature patterns
        body_lower = body.lower()
        matches = sum(1 for sig in self.soft_404_signatures if sig in body_lower)
        return matches >= 2

    def is_html_response(self, content_type: str, body: str) -> bool:
        """Check if a response is actually HTML (not the expected file type)."""
        if "text/html" in content_type.lower():
            return True
        if body.strip().startswith(("<!DOCTYPE", "<!doctype", "<html", "<HTML")):
            return True
        return False


# ── WAF Signatures ────────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "server": ["cloudflare"],
    },
    "akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn", "x-akamai-request-id"],
        "server": [],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["awselb", "amazons3"],
    },
    "imperva": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["imperva", "incapsula"],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
    "f5_bigip": {
        "headers": ["x-wa-info", "x-cnection"],
        "server": ["bigip", "big-ip", "f5"],
    },
    "barracuda": {
        "headers": ["barra_counter_session"],
        "server": ["barracuda"],
    },
    "fortinet": {
        "headers": ["fortiwafsid"],
        "server": ["fortiweb"],
    },
}

# ── Soft-404 Signatures ──────────────────────────────────────────────────────

SOFT_404_PATTERNS = [
    "page not found", "404 not found", "not found", "page doesn't exist",
    "page does not exist", "no results found", "nothing here",
    "sorry, we couldn't find", "the page you requested",
    "this page could not be found", "resource not found",
    "error 404", "oops!", "we can't find", "does not exist",
]

# ── SPA Signatures ───────────────────────────────────────────────────────────

SPA_PATTERNS = [
    r'<div\s+id="root"', r'<div\s+id="app"', r'<div\s+id="__next"',
    r'<div\s+id="__nuxt"', r'<script\s+src="[^"]*bundle[^"]*\.js"',
    r'<script\s+src="[^"]*chunk[^"]*\.js"', r'<script\s+src="[^"]*main\.[a-f0-9]+\.js"',
    r'ng-app=', r'data-reactroot', r'data-v-[a-f0-9]',
    r'__NEXT_DATA__', r'__NUXT__', r'window\.__INITIAL_STATE__',
]

# ── CMS Detection Patterns ──────────────────────────────────────────────────

CMS_PATTERNS = {
    "wordpress": [
        r'/wp-content/', r'/wp-includes/', r'<meta name="generator" content="WordPress',
        r'/wp-json/', r'/xmlrpc\.php',
    ],
    "joomla": [
        r'/media/system/', r'<meta name="generator" content="Joomla',
        r'/administrator/', r'/components/com_',
    ],
    "drupal": [
        r'Drupal\.settings', r'<meta name="Generator" content="Drupal',
        r'/sites/default/files/', r'/core/misc/drupal\.js',
    ],
    "shopify": [
        r'cdn\.shopify\.com', r'Shopify\.theme', r'<meta name="shopify',
    ],
}


def _structural_hash(html: str) -> str:
    """
    Generate a hash of HTML tag structure, ignoring text content.
    This allows comparing page layouts even when dynamic content changes.
    """
    # Extract just the tag structure
    tags = re.findall(r'</?[a-zA-Z][a-zA-Z0-9]*[^>]*>', html)
    # Normalize — keep only tag names and key attributes
    normalized = []
    for tag in tags[:200]:  # Cap at 200 tags for performance
        match = re.match(r'</?([a-zA-Z][a-zA-Z0-9]*)', tag)
        if match:
            normalized.append(match.group(0).lower())
    structure = "|".join(normalized)
    return hashlib.md5(structure.encode()).hexdigest()


class BaselineProfiler:
    """Run pre-scan baseline profiling against a target."""

    def __init__(self, target: str, timeout: int = 10, ui=None):
        self.target = target
        self.base_url = f"https://{target}" if not target.startswith("http") else target
        self.timeout = timeout
        self.ui = ui
        self.session = None
        if _requests:
            self.session = _requests.Session()
            self.session.headers.update({"User-Agent": "Mozilla/5.0 GhostRecon/3.0"})
            self.session.verify = False

    def profile(self) -> BaselineProfile:
        """Run all profiling checks and return a complete baseline."""
        if self.ui:
            self.ui.section("Baseline Profiling")

        profile = BaselineProfile(target=self.target, base_url=self.base_url)

        # 1. Default response fingerprint
        self._profile_default_response(profile)

        # 2. Soft-404 detection
        self._profile_soft_404(profile)

        # 3. Response timing baseline
        self._profile_timing(profile)

        # 4. WAF detection
        self._profile_waf(profile)

        # 5. Technology & CMS detection
        self._profile_technology(profile)

        # 6. SPA detection
        self._profile_spa(profile)

        if self.ui:
            self._print_profile_summary(profile)

        return profile

    def _get(self, url: str) -> Any:
        """Safe HTTP GET with timeout."""
        if not self.session:
            return None
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True)
        except Exception:
            return None

    def _profile_default_response(self, profile: BaselineProfile):
        """Capture the default homepage response fingerprint."""
        if self.ui:
            self.ui.info("Fingerprinting default response...")

        resp = self._get(self.base_url)
        if not resp:
            return

        profile.default_status = resp.status_code
        profile.default_content_length = len(resp.text)
        profile.default_content_type = resp.headers.get("Content-Type", "")
        profile.default_structural_hash = _structural_hash(resp.text)
        profile.server = resp.headers.get("Server", "")

    def _profile_soft_404(self, profile: BaselineProfile):
        """Detect custom error pages that return HTTP 200 instead of 404."""
        if self.ui:
            self.ui.info("Detecting soft-404 pages...")

        # Probe 3 random non-existent paths
        random_paths = [
            f"/ghostrecon_404_test_{uuid.uuid4().hex[:8]}",
            f"/this_page_definitely_does_not_exist_{uuid.uuid4().hex[:6]}",
            f"/random_nonexistent_{uuid.uuid4().hex[:10]}.html",
        ]

        responses = []
        for path in random_paths:
            resp = self._get(f"{self.base_url}{path}")
            if resp and resp.status_code == 200:
                responses.append(resp)

        if len(responses) >= 2:
            # If 2+ random paths return 200, this is a soft-404 target
            hashes = [_structural_hash(r.text) for r in responses]
            # If structural hashes are similar, it's the same error template
            if len(set(hashes)) <= 2:  # Allow for minor variation
                profile.soft_404_detected = True
                profile.soft_404_fingerprint = hashes[0]
                profile.soft_404_content_length = len(responses[0].text)

                # Extract text patterns from the error page
                body_lower = responses[0].text.lower()
                profile.soft_404_signatures = [
                    p for p in SOFT_404_PATTERNS if p in body_lower
                ]

                if self.ui:
                    self.ui.warn("Soft-404 detected — target returns 200 for non-existent pages")

    def _profile_timing(self, profile: BaselineProfile):
        """Measure baseline response times for timing-based detection calibration."""
        if self.ui:
            self.ui.info("Measuring response time baseline...")

        times = []
        for _ in range(5):
            start = time.time()
            resp = self._get(self.base_url)
            elapsed = time.time() - start
            if resp:
                times.append(elapsed)

        if len(times) >= 3:
            profile.baseline_times = times
            profile.baseline_mean = statistics.mean(times)
            profile.baseline_stdev = statistics.stdev(times) if len(times) > 1 else 0.1

            if self.ui:
                self.ui.info(
                    f"Response time: μ={profile.baseline_mean:.3f}s, "
                    f"σ={profile.baseline_stdev:.3f}s"
                )

    def _profile_waf(self, profile: BaselineProfile):
        """Detect WAF/CDN from response headers."""
        if self.ui:
            self.ui.info("Detecting WAF/CDN...")

        resp = self._get(self.base_url)
        if not resp:
            return

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        server_lower = headers_lower.get("server", "").lower()

        for waf_name, sigs in WAF_SIGNATURES.items():
            # Check header presence
            for hdr in sigs.get("headers", []):
                if hdr.lower() in headers_lower:
                    profile.waf_detected = True
                    profile.waf_name = waf_name
                    profile.waf_headers[hdr] = headers_lower[hdr.lower()]
                    break

            # Check server header
            for srv in sigs.get("server", []):
                if srv in server_lower:
                    profile.waf_detected = True
                    profile.waf_name = waf_name
                    break

            if profile.waf_detected:
                break

        if profile.waf_detected and self.ui:
            self.ui.warn(f"WAF detected: {profile.waf_name}")

    def _profile_technology(self, profile: BaselineProfile):
        """Detect technologies from headers and HTML content."""
        if self.ui:
            self.ui.info("Fingerprinting technologies...")

        resp = self._get(self.base_url)
        if not resp:
            return

        # Server header
        profile.server = resp.headers.get("Server", "unknown")

        # X-Powered-By
        powered_by = resp.headers.get("X-Powered-By", "")
        if powered_by:
            profile.technologies.append(powered_by)

        # Framework detection from headers
        if "X-AspNet-Version" in resp.headers:
            profile.technologies.append(f"ASP.NET {resp.headers['X-AspNet-Version']}")
        if "X-Drupal-Cache" in resp.headers:
            profile.technologies.append("Drupal")
            profile.cms = "drupal"

        # CMS detection from body
        body = resp.text[:5000]
        for cms_name, patterns in CMS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    profile.cms = cms_name
                    if cms_name not in [t.lower() for t in profile.technologies]:
                        profile.technologies.append(cms_name.title())
                    break

    def _profile_spa(self, profile: BaselineProfile):
        """Detect Single Page Application frameworks."""
        resp = self._get(self.base_url)
        if not resp:
            return

        body = resp.text[:10000]
        for pattern in SPA_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                profile.is_spa = True
                break

        if profile.is_spa and self.ui:
            self.ui.info("SPA detected — dynamic content; false positive filters activated")

    def _print_profile_summary(self, profile: BaselineProfile):
        """Print a summary of the baseline profile."""
        if not self.ui:
            return

        self.ui.blank()
        self.ui.subsection("Baseline Profile")
        self.ui.info(f"Server: {profile.server or 'unknown'}")
        self.ui.info(f"Technologies: {', '.join(profile.technologies) or 'none detected'}")
        if profile.cms:
            self.ui.info(f"CMS: {profile.cms}")
        self.ui.info(f"SPA: {'Yes' if profile.is_spa else 'No'}")
        self.ui.info(f"WAF: {profile.waf_name if profile.waf_detected else 'None detected'}")
        self.ui.info(f"Soft-404: {'Detected' if profile.soft_404_detected else 'Not detected'}")
        self.ui.info(f"Timing: μ={profile.baseline_mean:.3f}s σ={profile.baseline_stdev:.3f}s")
        self.ui.blank()
