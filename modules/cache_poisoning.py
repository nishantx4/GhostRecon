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

        # 2. Try to poison the cache with an unkeyed header
        canary = f"ghostrecon-cache-{uuid.uuid4().hex[:6]}"
        cache_buster = f"?cb={canary}"
        target_url = self.base_url + cache_buster
        
        poison_headers = {
            "X-Forwarded-Host": canary,
            "X-Original-URL": f"/{canary}",
            "X-Host": canary
        }

        try:
            # Send poisoning request
            s.get(target_url, headers=poison_headers, timeout=self.timeout)
            time.sleep(1) # wait a moment for cache
            
            # Send clean request (without headers) to see if poisoned response was cached
            clean_resp = s.get(target_url, timeout=self.timeout)
            
            if canary in clean_resp.text:
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
                    validation_steps=["cache_headers_detected", "canary_cached"]
                )
                 self.ui.find("high", "Web Cache Poisoning Confirmed", self.base_url)
                 return
                 
        except Exception:
            pass

        self.ui.info("No Cache Poisoning vulnerabilities detected.")
