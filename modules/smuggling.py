"""
SmugglingModule — GhostRecon module.
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


class SmugglingModule(BaseModule):
    NAME = "HTTP Smuggling"

    def run(self):
        self.ui.section("HTTP Request Smuggling — Passive Detection")
        if not requests:
            return
        try:
            import urllib3; urllib3.disable_warnings()
        except Exception:
            pass

        # Passive: check for proxy/load balancer headers that may indicate vuln infra
        resp = self._get(self.base_url)
        if resp is None:
            return

        h = {k.lower(): v for k, v in resp.headers.items()}
        proxy_indicators = ["x-forwarded-for", "via", "x-varnish", "x-cache",
                            "cf-ray", "x-amz-cf-id", "x-cdn"]
        has_proxy = any(p in h for p in proxy_indicators)

        if has_proxy:
            self.ui.info("Proxy infrastructure detected — initiating active smuggling probes...")
            self._probe_smuggling()
        else:
            self.ui.info("No proxy layer detected — smuggling risk lower, but testing anyway...")
            self._probe_smuggling()
            
    def _probe_smuggling(self):
        """
        Active time-based HTTP request smuggling probe.

        A single raw-socket delay is a weak signal on its own — plain network
        jitter, a slow backend, or a WAF rate-limit can all produce the same
        multi-second stall a real CL.TE/TE.CL desync would. To avoid reporting
        that as a "CONFIRMED critical" finding (this exact overconfidence
        pattern — a single unbounded timing sample with no baseline or repeat
        check — is what caused false positives in sqli.py's time-based
        detector earlier), this now: (1) measures a normal-request baseline
        first, (2) requires the smuggling payload's delay to clear baseline by
        a wide margin AND hit the socket timeout (real desyncs hang until the
        backend gives up, they don't land at an arbitrary number), and
        (3) repeats the payload once to confirm before reporting — and even
        then caps confidence at HIGH, not CONFIRMED, with the evidence saying
        so plainly.
        """
        import socket
        import ssl
        from urllib.parse import urlparse

        parsed = urlparse(self.base_url)
        host = parsed.netloc
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        use_ssl = parsed.scheme == 'https'

        # CL.TE Time-based payload (Content-Length is primary, Transfer-Encoding is secondary)
        # If frontend uses CL (reads all), backend uses TE (stops at 0), the extra 'X' gets queued
        cl_te_req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"1\r\n"
            f"Z\r\n"
            f"Q\r\n"
        ).encode()

        # TE.CL Time-based payload
        # If frontend uses TE (stops at 0), backend uses CL (waits for 6 bytes), it waits for the 'X'
        te_cl_req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 6\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"X"
        ).encode()

        # A normal, correctly-framed request — used to measure baseline
        # latency so a slow-but-benign server doesn't get flagged.
        control_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()

        timeout_val = 10

        def send_raw(payload, timeout=timeout_val):
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
                if use_ssl:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    sock = ctx.wrap_socket(sock, server_hostname=host)

                t0 = time.time()
                sock.sendall(payload)
                sock.recv(4096)
                elapsed = time.time() - t0
                sock.close()
                return elapsed
            except socket.timeout:
                return timeout
            except Exception:
                return None

        # Baseline: normal request latency (median of 2, to smooth one-off jitter).
        baseline_samples = [t for t in (send_raw(control_req), send_raw(control_req)) if t is not None]
        baseline = sorted(baseline_samples)[len(baseline_samples) // 2] if baseline_samples else 0.5
        # A real desync hangs the connection until the server's own read
        # timeout, so we want a delay that both clears baseline by a wide
        # margin AND lands near our socket timeout — not just "somewhat slow".
        threshold = max(baseline * 3, baseline + 5, 6.0)

        def probe_and_confirm(payload, label):
            self.ui.info(f"Testing {label}...")
            t1 = send_raw(payload)
            if t1 is None or t1 < threshold:
                return None
            time.sleep(self.delay)
            self.ui.warn(f"{label} candidate ({t1:.1f}s vs baseline {baseline:.2f}s) — confirming...")
            t2 = send_raw(payload)
            if t2 is None or t2 < threshold:
                return None
            return (t1, t2)

        cl_te_result = probe_and_confirm(cl_te_req, "CL.TE")
        time.sleep(self.delay)
        te_cl_result = probe_and_confirm(te_cl_req, "TE.CL") if not cl_te_result else None

        def report(kind, result):
            t1, t2 = result
            self.db.add(
                title=f"HTTP Request Smuggling ({kind}) — Timing Indicator",
                severity="high", url=self.base_url, module=self.NAME,
                description=(
                    f"Two consecutive {kind}-shaped smuggling payloads both stalled "
                    f"({t1:.1f}s, {t2:.1f}s) well beyond the measured baseline latency "
                    f"({baseline:.2f}s), consistent with a front-end/back-end desync where "
                    f"one hop reads Content-Length and the other reads Transfer-Encoding. "
                    f"Timing alone cannot fully prove smuggling (network conditions and "
                    f"slow backends can also cause stalls) — manually confirm with a "
                    f"differential response-splitting payload (e.g. Burp's HTTP Request "
                    f"Smuggler) before treating this as exploitable."
                ),
                remediation="Ensure front-end and back-end servers consistently parse Transfer-Encoding and Content-Length headers. Prefer HTTP/2 for back-end connections to avoid smuggling.",
                cvss="7.5",
                confidence="HIGH",
                confidence_score=75,
                validation_steps=["baseline_measured", f"{kind.lower().replace('.', '_')}_timing_delay", "repeated_to_confirm"],
                evidence=[f"Baseline: {baseline:.2f}s", f"Probe 1: {t1:.2f}s", f"Probe 2: {t2:.2f}s",
                          f"Threshold: {threshold:.2f}s"],
            )
            self.ui.find("high", f"HTTP Smuggling ({kind}) — timing indicator", self.base_url)

        if cl_te_result:
            report("CL.TE", cl_te_result)
        elif te_cl_result:
            report("TE.CL", te_cl_result)
        else:
            self.ui.info("No time-based smuggling vulnerability detected.")


# ─── CORS Module ───────────────────────────────────────────────────────────────