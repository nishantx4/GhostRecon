"""
CachePoisoningModule — GhostRecon module.
Detects Web Cache Poisoning by injecting unkeyed headers.
"""
import time
import uuid

try:
    import requests
except ImportError:
    requests = None

from modules import BaseModule


class CachePoisoningModule(BaseModule):
    NAME = "Cache Poisoning"

    def run(self):
        self.ui.section("Cache Poisoning Detection")
        if not requests:
            return

        s = self._session()
        
        # 1. Check if the site uses caching
        try:
            resp = s.get(self.base_url, timeout=self.timeout)
            cache_headers = [k.lower() for k in resp.headers.keys()]
            has_cache = any(h in cache_headers for h in ["x-cache", "age", "cf-cache-status", "x-varnish", "via"])
            
            if not has_cache:
                self.ui.info("No caching headers detected. Target is likely not vulnerable to cache poisoning.")
                return
        except Exception:
            return

        # 2. Try to poison the cache with an unkeyed header.
        # IMPORTANT: the cache-buster (to force a fresh cache entry) and the
        # poison marker (to prove the unkeyed header leaked into cached
        # content) MUST be two different, unrelated values. The original
        # code reused the same canary for both — since it was embedded in
        # the URL's own query string, ANY app that echoes its own URL
        # anywhere in the page (canonical links, OG tags, pagination, a
        # self-referencing form action — all extremely common) would show
        # the canary in the "clean" response with zero actual cache
        # poisoning involved, guaranteeing a false positive on almost any
        # cache-fronted site.
        cache_buster = uuid.uuid4().hex[:8]
        poison_marker = f"ghostrecon-poison-{uuid.uuid4().hex[:10]}"
        target_url = f"{self.base_url}?cb={cache_buster}"

        poison_headers = {
            "X-Forwarded-Host": poison_marker,
            "X-Original-URL": f"/{poison_marker}",
            "X-Host": poison_marker,
        }

        try:
            # Baseline: confirm the poison marker is NOT already present
            # (e.g. via direct per-request header reflection unrelated to
            # caching) before we poison anything.
            baseline_resp = s.get(target_url, timeout=self.timeout)
            if poison_marker in baseline_resp.text:
                self.ui.info("No Cache Poisoning vulnerabilities detected.")
                return

            # Send poisoning request (carries the unkeyed header)
            s.get(target_url, headers=poison_headers, timeout=self.timeout)
            time.sleep(1)  # wait a moment for cache to store the response

            # Send a CLEAN request — no poison headers — to the SAME cache
            # key. If the poison marker shows up here, the server cached the
            # poisoned response and is now serving it to unrelated requests.
            clean_resp = s.get(target_url, timeout=self.timeout)

            if poison_marker in clean_resp.text:
                 self.db.add(
                    title="Web Cache Poisoning",
                    severity="high", url=self.base_url, module=self.NAME,
                    description=(
                        "The application uses an unkeyed header (e.g., X-Forwarded-Host) to generate content, "
                        "and caches the resulting response. An attacker can poison the cache for normal users."
                    ),
                    remediation="Disable caching for endpoints that process unkeyed headers, or include all influential headers in the cache key.",
                    cvss="7.5",
                    confidence="CONFIRMED",
                    confidence_score=95,
                    evidence=[f"Poison marker '{poison_marker}' (sent only via X-Forwarded-Host/X-Host/X-Original-URL) "
                              f"was reflected in a subsequent request that sent none of those headers."],
                    validation_steps=["cache_headers_detected", "baseline_clean", "poison_marker_cached_and_served_unpoisoned"]
                )
                 self.ui.find("high", "Web Cache Poisoning Confirmed", self.base_url)
                 return

        except Exception:
            pass

        self.ui.info("No Cache Poisoning vulnerabilities detected.")
