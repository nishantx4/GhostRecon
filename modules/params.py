"""
ParamModule — GhostRecon module.
"""
import re
import time
import urllib.parse

try:
    import requests
    from requests.exceptions import RequestException
except ImportError:
    requests = None

from modules import BaseModule


class ParamModule(BaseModule):
    NAME = "Param Discovery"

    def run(self):
        self.ui.section("Parameter Discovery")
        # Params are now collected via ReconModule crawl
        # This module adds extra common params if recon didn't find any
        endpoints = self.ctx.get("endpoints", [self.base_url])
        params_found = []

        for ep in endpoints[:20]:
            parsed = urllib.parse.urlparse(ep)
            if parsed.query:
                for k in urllib.parse.parse_qs(parsed.query).keys():
                    params_found.append((ep, k))

        self.ui.info(f"Parameters in scope: {len(params_found)} from {len(endpoints)} endpoints")
        self.ctx["discovered_params"] = params_found


# ─── Nuclei Simulation Module ──────────────────────────────────────────────────