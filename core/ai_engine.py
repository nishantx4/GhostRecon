"""
AIEngine — NVIDIA NIM powered hunting + analysis engine.
Uses qwen/qwen3.5-122b-a10b with thinking mode via direct requests (streaming SSE).
Falls back to a local rule-based engine when no API key is configured.

Active hunting roles:
  - analyze_endpoint()      → inspect a live HTTP response for vulns
  - suggest_payloads()      → generate targeted test payloads for a param
  - analyze_js_content()    → deep-dive JS file for hidden secrets/logic
  - analyze_headers()       → assess header combination risks
  - analyze_idor_response() → determine if a response leaks private data
  - analyze_sqli_error()    → fingerprint DB type from error messages
  - prioritize_endpoints()  → rank endpoints by bug bounty value
  - analyze_chains()        → identify vuln chains across all findings
  - generate_report()       → write a professional bug bounty report
"""
import json
import requests as _requests
import core.config as config


# ── Model config ──────────────────────────────────────────────────────────────
NVIDIA_INVOKE_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NVIDIA_MODEL      = "qwen/qwen3.5-122b-a10b"

# Models that support the qwen-style thinking mode kwarg.
_THINKING_MODELS = ("qwen/", "deepseek-ai/")


def _supports_thinking(model: str) -> bool:
    return any(model.startswith(p) for p in _THINKING_MODELS)


class AIEngine:
    def __init__(self, api_key: str | None = None, ui=None):
        self.api_key = api_key
        self.ui      = ui

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    # ── Internal streaming call ───────────────────────────────────────────────

    def _call(self, system: str, user: str, max_tokens: int = 2048,
              stream_to_ui: bool = False) -> str | None:
        """
        POST to NVIDIA NIM with streaming SSE.
        Collects the full streamed response and returns it as a string.
        If stream_to_ui=True, prints tokens live to terminal as they arrive.
        """
        if not self.api_key:
            return None

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }
        payload = {
            "model": config.get_model(),
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.60,
            "top_p": 0.95,
            "stream": True,
        }
        if _supports_thinking(config.get_model()):
            payload["chat_template_kwargs"] = {"enable_thinking": True}

        try:
            resp = _requests.post(
                NVIDIA_INVOKE_URL,
                headers=headers,
                json=payload,
                stream=True,
                timeout=60,
            )
            resp.raise_for_status()

            full_text = []
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line

                # SSE lines start with "data: "
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]  # strip "data: "
                if data_str.strip() == "[DONE]":
                    break

                try:
                    chunk = json.loads(data_str)
                    delta = chunk["choices"][0]["delta"]
                    token = delta.get("content") or ""
                    # thinking tokens are in reasoning_content — skip for output
                    if token:
                        full_text.append(token)
                        if stream_to_ui and self.ui:
                            self.ui.raw(token, end="", flush=True)
                except (KeyError, json.JSONDecodeError):
                    continue

            if stream_to_ui and self.ui:
                self.ui.blank()

            return "".join(full_text).strip() or None

        except Exception as e:
            if self.ui:
                self.ui.error(f"NVIDIA AI error: {e}")
            return None

    def _print_ai(self, result: str):
        """Pretty-print an AI response block to terminal."""
        if self.ui and result:
            self.ui.blank()
            for line in result.split("\n"):
                self.ui.raw(f"    {line}")
            self.ui.blank()

    # =========================================================================
    # ACTIVE HUNTING METHODS  (called during scanning)
    # =========================================================================

    def analyze_endpoint(self, url: str, status: int, headers: dict,
                         body_snippet: str) -> str | None:
        """Called by ReconModule after crawling each endpoint."""
        if not self.enabled:
            return None
        if self.ui:
            self.ui.ai(f"AI inspecting endpoint: {url}")
        system = (
            "You are an elite bug bounty hunter. Analyze this HTTP response and "
            "identify in 2-3 bullet points: (1) immediate red flags, "
            "(2) vulnerability classes to test here, "
            "(3) any tech/framework hints. Be concise and specific. No fluff."
        )
        user = (
            f"URL: {url}\n"
            f"Status: {status}\n"
            f"Response Headers: {json.dumps(dict(list(headers.items())[:15]))}\n"
            f"Body snippet (first 500 chars):\n{body_snippet[:500]}"
        )
        return self._call(system, user, max_tokens=400)

    def suggest_payloads(self, param: str, url: str,
                         vuln_type: str = "xss") -> list[str]:
        """
        Get AI-tailored payloads for a parameter based on name + context.
        Returns a list of payload strings (up to 10).
        """
        if not self.enabled:
            return []
        if self.ui:
            self.ui.ai(f"AI generating {vuln_type.upper()} payloads for param '{param}'...")
        system = (
            "You are a web security expert. Generate highly targeted payloads. "
            "Output ONLY a JSON array of payload strings, no explanations. "
            'Example: ["payload1", "payload2"]'
        )
        user = (
            f"Vulnerability type: {vuln_type}\n"
            f"Parameter name: {param}\n"
            f"Target URL: {url}\n"
            "Generate 8 effective, context-aware payloads. "
            "Consider the param name when choosing payloads. "
            "Return ONLY a valid JSON array."
        )
        result = self._call(system, user, max_tokens=500)
        if result:
            try:
                start = result.find("[")
                end   = result.rfind("]") + 1
                if start != -1 and end > start:
                    payloads = json.loads(result[start:end])
                    return [str(p) for p in payloads[:10]]
            except Exception:
                pass
        return []

    def analyze_js_content(self, url: str, content: str) -> str | None:
        """Deep JS analysis — hidden endpoints, auth flaws, logic bugs, secrets."""
        if not self.enabled:
            return None
        if self.ui:
            self.ui.ai(f"AI deep-analyzing JS: {url}")
        system = (
            "You are a JavaScript security researcher. Analyze this JS code and identify: "
            "(1) hidden API endpoints or routes, "
            "(2) authentication/authorization logic flaws, "
            "(3) hardcoded secrets or sensitive values (beyond obvious patterns), "
            "(4) dangerous function calls (eval, innerHTML, document.write), "
            "(5) client-side access control that can be bypassed. "
            "Use bullet points. Focus only on exploitable findings."
        )
        user = f"JS file: {url}\n\nContent (first 3000 chars):\n{content[:3000]}"
        return self._call(system, user, max_tokens=700)

    def analyze_headers(self, url: str, headers: dict,
                        missing: list[str]) -> str | None:
        """Assess combined risk of header configuration — real attack chains."""
        if not self.enabled:
            return None
        if self.ui:
            self.ui.ai("AI analyzing header security posture...")
        system = (
            "You are a web security expert. Given HTTP response headers and a list of "
            "missing security headers, explain in 3-4 bullet points: "
            "(1) what combined attack chains are possible, "
            "(2) the real-world exploitability, "
            "(3) the highest-priority fix. Be direct and technical."
        )
        user = (
            f"URL: {url}\n"
            f"Present headers: {json.dumps(dict(list(headers.items())[:20]))}\n"
            f"Missing security headers: {missing}"
        )
        return self._call(system, user, max_tokens=500)

    def analyze_idor_response(self, url: str, response_body: str,
                               id_value: str) -> dict | None:
        """
        Assess whether a 200-OK response actually exposes private data.
        Returns dict: {'is_idor': bool, 'confidence': str, 'reason': str}
        """
        if not self.enabled:
            return None
        system = (
            "You are a bug bounty hunter analyzing HTTP responses for IDOR vulnerabilities. "
            "Determine if this response exposes private user data. "
            "Respond with ONLY valid JSON (no other text): "
            '{"is_idor": true/false, "confidence": "high/medium/low", "reason": "one sentence"}'
        )
        user = (
            f"URL: {url}\n"
            f"ID tested: {id_value}\n"
            f"Response body (first 1000 chars):\n{response_body[:1000]}"
        )
        result = self._call(system, user, max_tokens=150)
        if result:
            try:
                start = result.find("{")
                end   = result.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(result[start:end])
            except Exception:
                pass
        return None

    def analyze_sqli_error(self, url: str, param: str,
                            error_text: str) -> str | None:
        """Analyze a potential SQL error — identify DB type, confirm injection, suggest next payloads."""
        if not self.enabled:
            return None
        system = (
            "You are a SQL injection expert. Analyze this error message and identify: "
            "(1) the database type (MySQL/MSSQL/PostgreSQL/SQLite/Oracle), "
            "(2) whether this is a true SQL injection or a false positive, "
            "(3) the next 2 payloads to confirm and exploit it. "
            "Be concise and technical."
        )
        user = (
            f"URL: {url}\nParameter: {param}\n"
            f"Error / Response snippet:\n{error_text[:800]}"
        )
        return self._call(system, user, max_tokens=400)

    def analyze_cors(self, url: str, origin: str, acao: str,
                     acac: str) -> str | None:
        """Explain the real-world exploitability of a reflected/loose CORS policy."""
        if not self.enabled:
            return None
        system = (
            "You are a web security expert. Given a CORS response, explain in 2-3 "
            "bullet points whether this is exploitable, what an attacker can read, "
            "and the prerequisites (credentials, victim session). Be concise."
        )
        user = (
            f"URL: {url}\nReflected/allowed Origin: {origin}\n"
            f"Access-Control-Allow-Origin: {acao}\n"
            f"Access-Control-Allow-Credentials: {acac}"
        )
        return self._call(system, user, max_tokens=300)

    def suggest_ssrf_payloads(self, param: str, url: str) -> list[str]:
        """Ask AI for target-aware SSRF bypass payloads. Returns a list of strings."""
        if not self.enabled:
            return []
        system = (
            "You are an SSRF expert. Output ONLY a JSON array of SSRF payload URLs "
            "that bypass common filters (encoding, redirects, IPv6, decimal IP, "
            "cloud metadata). No explanations."
        )
        user = f"Parameter: {param}\nTarget: {url}\nReturn 8 payloads as a JSON array."
        result = self._call(system, user, max_tokens=400)
        if result:
            try:
                start = result.find("[")
                end   = result.rfind("]") + 1
                if start != -1 and end > start:
                    return [str(p) for p in json.loads(result[start:end])[:10]]
            except Exception:
                pass
        return []

    def analyze_ssrf_response(self, url: str, payload: str,
                              body_snippet: str) -> dict | None:
        """Decide whether a response indicates a real SSRF. Returns dict or None."""
        if not self.enabled:
            return None
        system = (
            "You are an SSRF expert. Decide if this response proves the server made "
            "the requested internal/metadata request. Respond with ONLY JSON: "
            '{"is_ssrf": true/false, "confidence": "high/medium/low", "reason": "one sentence"}'
        )
        user = (
            f"URL: {url}\nPayload: {payload}\n"
            f"Response (first 800 chars):\n{body_snippet[:800]}"
        )
        result = self._call(system, user, max_tokens=150)
        if result:
            try:
                start = result.find("{")
                end   = result.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(result[start:end])
            except Exception:
                pass
        return None

    def analyze_graphql(self, url: str, schema_snippet: str) -> str | None:
        """Highlight the most abusable types/mutations from an introspected schema."""
        if not self.enabled:
            return None
        system = (
            "You are a GraphQL security researcher. From this introspection result, "
            "list in bullet points the most security-sensitive types/mutations to "
            "test (auth, user data, file ops, admin), and any batching/DoS risk. Be brief."
        )
        user = f"Endpoint: {url}\nSchema (first 2000 chars):\n{schema_snippet[:2000]}"
        return self._call(system, user, max_tokens=400)

    def analyze_smuggling(self, url: str, headers: dict) -> str | None:
        """Assess request-smuggling exposure from front-end/proxy headers."""
        if not self.enabled:
            return None
        system = (
            "You are an HTTP request smuggling expert. Given these response headers, "
            "assess in 2-3 bullets the likelihood of a CL.TE / TE.CL desync and which "
            "front-end/back-end pairing is implied. Be concise."
        )
        user = f"URL: {url}\nHeaders: {json.dumps(dict(list(headers.items())[:20]))}"
        return self._call(system, user, max_tokens=300)

    def validate_secret(self, label: str, snippet: str) -> dict | None:
        """Judge whether an exposed-file snippet contains a real secret. Returns dict."""
        if not self.enabled:
            return None
        system = (
            "You are a secrets-detection expert. Decide if this content contains a "
            "real, sensitive secret (credentials, private key, live API token) versus "
            "a placeholder/example. Respond with ONLY JSON: "
            '{"is_secret": true/false, "confidence": "high/medium/low", "reason": "one sentence"}'
        )
        user = f"File type: {label}\nContent (first 800 chars):\n{snippet[:800]}"
        result = self._call(system, user, max_tokens=150)
        if result:
            try:
                start = result.find("{")
                end   = result.rfind("}") + 1
                if start != -1 and end > start:
                    return json.loads(result[start:end])
            except Exception:
                pass
        return None

    def prioritize_endpoints(self, endpoints: list[str]) -> list[str]:
        """
        Rank the top 20 most interesting endpoints for security testing.
        Returns a reordered list (highest priority first).
        """
        if not self.enabled or not endpoints:
            return endpoints
        if self.ui:
            self.ui.ai(f"AI prioritizing {len(endpoints)} endpoints for testing...")
        system = (
            "You are a bug bounty hunter. Given a list of URLs, select and rank "
            "the TOP 20 most interesting for security testing. "
            "Prioritize: API endpoints, user/account/admin paths, endpoints with ID "
            "parameters, file operations, payment/billing/auth paths. "
            "Return ONLY a valid JSON array of the top 20 URLs in priority order. "
            "No explanations, no other text."
        )
        sample = endpoints[:80]
        user   = "Endpoints:\n" + "\n".join(sample)
        result = self._call(system, user, max_tokens=1000)
        if result:
            try:
                start = result.find("[")
                end   = result.rfind("]") + 1
                if start != -1 and end > start:
                    ranked     = json.loads(result[start:end])
                    ranked_set = set(ranked)
                    rest       = [e for e in endpoints if e not in ranked_set]
                    return ranked + rest
            except Exception:
                pass
        return endpoints

    # =========================================================================
    # POST-SCAN ANALYSIS
    # =========================================================================

    def analyze_chains(self, target: str, findings: list) -> str | None:
        """Full vulnerability chain analysis after all modules complete."""
        if not findings:
            if self.ui:
                self.ui.info("No findings to chain-analyze.")
            return None

        summary = "\n".join(
            f"- [{f['severity'].upper()}] {f['title']} | {f['url']} | module: {f['module']}"
            for f in findings
        )

        if self.enabled:
            if self.ui:
                self.ui.ai("Sending findings to NVIDIA AI for chain analysis...")
            system = (
                "You are a world-class bug bounty hunter with thinking mode enabled. "
                "Analyze these vulnerability findings and deliver: "
                "1) Attack chains where combining findings escalates impact, "
                "2) The single highest-impact attack path with step-by-step PoC, "
                "3) Exploitation priority ranked by bounty value, "
                "4) Estimated bounty range per finding class ($), "
                "5) Top 3 findings with PoC outlines. "
                "Be technical, specific, and directly actionable."
            )
            user = (
                f"Target: {target}\n\nFindings:\n{summary}\n\n"
                "Identify all chaining opportunities, the highest-impact attack path, "
                "estimated bounty ranges, and top 3 PoC outlines."
            )
            result = self._call(system, user, max_tokens=3000)
            if result:
                self._print_ai(result)
                return result

        # Local fallback
        return self._local_chain_analysis(target, findings)

    def generate_report(self, target: str, findings: list,
                        context: dict) -> str | None:
        """AI-enhanced Markdown bug bounty report."""
        detail = "\n\n".join(
            f"[{f['severity'].upper()}] {f['title']}\n"
            f"URL: {f['url']}\nCVSS: {f.get('cvss','N/A')}\n"
            f"Description: {f['description']}\nRemediation: {f['remediation']}"
            for f in findings
        )
        if self.enabled:
            if self.ui:
                self.ui.ai("NVIDIA AI generating enhanced bug bounty report...")
            system = (
                "You are an expert bug bounty report writer. "
                "Write professional, detailed, and accurate reports suitable for "
                "HackerOne, Bugcrowd, or direct submission. Include: executive summary, "
                "severity breakdown, full technical details per finding, "
                "impact analysis, PoC steps, and remediation priority matrix. "
                "Format in clean Markdown."
            )
            user = (
                f"Target: {target}\n"
                f"Subdomains found: {len(context.get('subdomains', []))}\n"
                f"Endpoints discovered: {len(context.get('endpoints', []))}\n\n"
                f"Findings:\n{detail}\n\n"
                "Write a complete, professional bug bounty report in Markdown."
            )
            return self._call(system, user, max_tokens=6000)
        return None

    # =========================================================================
    # API KEY MANAGEMENT
    # =========================================================================

    @staticmethod
    def test_key(api_key: str, ui=None) -> bool:
        """
        Send a minimal streaming test request to NVIDIA NIM.
        Returns True if the key works, False otherwise.
        """
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "text/event-stream",
            "Content-Type": "application/json",
        }
        payload = {
            "model": config.get_model(),
            "messages": [{"role": "user", "content": "Say the word OK and nothing else."}],
            "max_tokens": 10,
            "temperature": 0.60,
            "top_p": 0.95,
            "stream": True,
        }
        if _supports_thinking(config.get_model()):
            payload["chat_template_kwargs"] = {"enable_thinking": True}
        try:
            resp = _requests.post(
                NVIDIA_INVOKE_URL,
                headers=headers,
                json=payload,
                stream=True,
                timeout=30,
            )
            resp.raise_for_status()
            # Just need at least one valid data chunk
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8") if isinstance(raw_line, bytes) else raw_line
                if line.startswith("data: ") and line[6:].strip() != "[DONE]":
                    return True  # Got a valid response chunk
            return False
        except Exception as e:
            if ui:
                ui.error(f"API test failed: {e}")
            return False

    # =========================================================================
    # LOCAL FALLBACK ENGINE
    # =========================================================================

    def _local_chain_analysis(self, target: str, findings: list):
        def has(kw):
            return any(
                kw.lower() in f["title"].lower() or
                kw.lower() in f.get("description", "").lower()
                for f in findings
            )

        if self.ui:
            self.ui.subsection("Local Chain Analysis Engine (no AI key configured)")

        chains = []
        if has("ssrf") and (has(".env") or has("secret") or has("key")):
            chains.append(("SSRF → Credential Exposure → Cloud Takeover",    "P1 Critical", "$8k–$20k"))
        if has("idor") and has("auth"):
            chains.append(("IDOR + Weak Auth → Mass Data Exfiltration",      "P1/P2",       "$3k–$8k"))
        if has(".env") or has("backup") or has("exposed"):
            chains.append(("Exposed Secrets → Full Application Takeover",    "P1 Critical", "$5k–$15k"))
        if has("graphql") and has("idor"):
            chains.append(("GraphQL Introspection + IDOR → Mutation Abuse",  "P2 High",     "$2k–$5k"))
        if has("smuggling") or has("smuggl"):
            chains.append(("HTTP Smuggling → Session Hijacking",             "P1/P2",       "$4k–$12k"))
        if has("xss"):
            chains.append(("XSS → Session Token Theft → Account Takeover",   "P2 High",     "$1k–$4k"))
        if has("cors"):
            chains.append(("CORS Misconfiguration → Cross-Origin Cred Theft","P2 High",     "$1k–$3k"))
        if has("sqli") or has("sql injection"):
            chains.append(("SQL Injection → Database Dump → Full Compromise", "P1 Critical", "$5k–$25k"))

        if self.ui:
            if chains:
                self.ui.blank()
                for name, sev, bounty in chains:
                    self.ui.bullet(name)
                    self.ui.bullet(f"Severity: {sev}  |  Est. Bounty: {bounty}", indent=8)
                    self.ui.blank()
            else:
                self.ui.info("No chains detected — focus on individual high-severity findings.")

            order    = ["critical", "high", "medium", "low", "info"]
            sorted_f = sorted(findings, key=lambda f: order.index(f["severity"]))
            self.ui.blank()
            self.ui.subsection("Priority Order")
            bounty_map = {
                "critical": "$3k–$15k", "high": "$1k–$5k",
                "medium":   "$200–$1k", "low":  "$50–$200", "info": "$0–$50",
            }
            for i, f in enumerate(sorted_f[:8], 1):
                self.ui.bullet(
                    f"#{i} [{f['severity'].upper()}] {f['title']}  —  "
                    f"Est. {bounty_map.get(f['severity'], 'N/A')}",
                    indent=4,
                )
