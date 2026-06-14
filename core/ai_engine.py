"""
AIEngine — NVIDIA NIM (free tier) powered hunting + analysis engine.
Uses the OpenAI-compatible endpoint at https://integrate.api.nvidia.com/v1
Falls back to a local rule-based engine when no API key is configured.

Active hunting roles:
  - analyze_endpoint()     → inspect a live HTTP response for vulns
  - suggest_payloads()     → generate targeted test payloads for a param
  - analyze_js_content()   → deep-dive JS file for hidden secrets/logic
  - analyze_headers()      → assess header combination risks
  - analyze_idor_response()→ determine if a response leaks private data
  - analyze_chains()       → identify vuln chains across all findings
  - generate_report()      → write a professional bug bounty report
"""
import json


# ── Model config ──────────────────────────────────────────────────────────────
NVIDIA_BASE_URL = "https://integrate.api.nvidia.com/v1"
# Free-tier model — Qwen3 80B, fast and capable for security analysis
NVIDIA_MODEL    = "qwen/qwen3-next-80b-a3b-instruct"


class AIEngine:
    def __init__(self, api_key: str | None = None, ui=None):
        self.api_key = api_key
        self.ui      = ui
        self._client = None

        if api_key:
            try:
                from openai import OpenAI
                self._client = OpenAI(
                    base_url=NVIDIA_BASE_URL,
                    api_key=api_key,
                )
            except ImportError:
                if self.ui:
                    self.ui.warn("openai package not installed. Run: pip install openai")
                self._client = None

    @property
    def enabled(self) -> bool:
        return self._client is not None

    # ── Internal call ─────────────────────────────────────────────────────────

    def _call(self, system: str, user: str, max_tokens: int = 1024) -> str | None:
        if not self._client:
            return None
        try:
            resp = self._client.chat.completions.create(
                model=NVIDIA_MODEL,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user",   "content": user},
                ],
                max_tokens=max_tokens,
                temperature=0.6,
                top_p=0.7,
                stream=False,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            if self.ui:
                self.ui.error(f"NVIDIA AI error: {e}")
            return None

    def _print_ai(self, result: str):
        """Pretty-print an AI response to terminal."""
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
        """
        Called by ReconModule after crawling each endpoint.
        Returns a short AI note on interesting things to investigate.
        """
        if not self.enabled:
            return None

        self.ui.ai(f"AI inspecting endpoint: {url}")
        system = (
            "You are an elite bug bounty hunter. Analyze this HTTP response and "
            "identify in 2-3 bullet points: (1) any immediate red flags, "
            "(2) what vulnerability classes to test here, "
            "(3) any tech/framework hints. Be concise and specific."
        )
        user = (
            f"URL: {url}\n"
            f"Status: {status}\n"
            f"Response Headers: {json.dumps(dict(list(headers.items())[:15]))}\n"
            f"Body snippet (first 500 chars):\n{body_snippet[:500]}"
        )
        return self._call(system, user, max_tokens=300)

    def suggest_payloads(self, param: str, url: str,
                         vuln_type: str = "xss") -> list[str]:
        """
        Called by XSS / SQLi modules to get AI-tailored payloads
        based on the parameter name and context.
        Returns a list of payload strings (up to 10).
        """
        if not self.enabled:
            return []

        self.ui.ai(f"AI generating {vuln_type.upper()} payloads for param '{param}'...")
        system = (
            "You are a web security expert. Generate highly targeted payloads for "
            "the vulnerability type specified. Output ONLY a JSON array of payload "
            'strings, no explanations. Example: ["payload1", "payload2"]'
        )
        user = (
            f"Vulnerability type: {vuln_type}\n"
            f"Parameter name: {param}\n"
            f"Target URL: {url}\n"
            "Generate 8 effective, context-aware payloads. "
            "Consider the param name when choosing payloads. "
            "Return ONLY a JSON array."
        )
        result = self._call(system, user, max_tokens=400)
        if result:
            try:
                # Extract JSON array from response
                start = result.find("[")
                end   = result.rfind("]") + 1
                if start != -1 and end > start:
                    payloads = json.loads(result[start:end])
                    return [str(p) for p in payloads[:10]]
            except Exception:
                pass
        return []

    def analyze_js_content(self, url: str, content: str) -> str | None:
        """
        Deep JS analysis — finds logic flaws, hidden endpoints,
        auth bypass hints, and obfuscated secrets.
        """
        if not self.enabled:
            return None

        self.ui.ai(f"AI deep-analyzing JS: {url}")
        system = (
            "You are a JavaScript security researcher specializing in bug bounty. "
            "Analyze this JavaScript code and identify: "
            "(1) hidden API endpoints or routes, "
            "(2) authentication/authorization logic flaws, "
            "(3) hardcoded secrets or sensitive values (beyond obvious patterns), "
            "(4) dangerous function calls (eval, innerHTML, document.write), "
            "(5) client-side access control that can be bypassed. "
            "Be concise, use bullet points, focus on exploitable findings."
        )
        user = f"JS file: {url}\n\nContent (first 3000 chars):\n{content[:3000]}"
        return self._call(system, user, max_tokens=600)

    def analyze_headers(self, url: str, headers: dict,
                        missing: list[str]) -> str | None:
        """
        Assess the combined risk of the header configuration — not just
        individual missing headers, but what attack chains they enable.
        """
        if not self.enabled:
            return None

        self.ui.ai("AI analyzing header security posture...")
        system = (
            "You are a web security expert. Given HTTP response headers and a list of "
            "missing security headers, explain in 3-4 bullet points: "
            "(1) what combined attack chains are possible, "
            "(2) the real-world exploitability (not just theory), "
            "(3) the highest-priority fix. Be direct and technical."
        )
        user = (
            f"URL: {url}\n"
            f"Present headers: {json.dumps(dict(list(headers.items())[:20]))}\n"
            f"Missing security headers: {missing}"
        )
        return self._call(system, user, max_tokens=400)

    def analyze_idor_response(self, url: str, response_body: str,
                               id_value: str) -> dict | None:
        """
        Assess whether a 200-OK response actually exposes private data.
        Returns dict with keys: 'is_idor' (bool), 'confidence', 'reason'.
        """
        if not self.enabled:
            return None

        system = (
            "You are a bug bounty hunter analyzing HTTP responses for IDOR. "
            "Determine if this response exposes private user data. "
            'Respond with ONLY valid JSON: {"is_idor": true/false, '
            '"confidence": "high/medium/low", "reason": "one sentence"}'
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
        """
        Analyze a potential SQL error message to identify DB type,
        injectable point, and suggest next steps.
        """
        if not self.enabled:
            return None

        system = (
            "You are a SQL injection expert. Analyze this error message and identify: "
            "(1) the database type, "
            "(2) whether this is a true SQL injection or false positive, "
            "(3) the next 2 payloads to confirm and exploit it. "
            "Be concise and technical."
        )
        user = (
            f"URL: {url}\nParameter: {param}\n"
            f"Error / Response snippet:\n{error_text[:800]}"
        )
        return self._call(system, user, max_tokens=350)

    def prioritize_endpoints(self, endpoints: list[str]) -> list[str]:
        """
        Given a list of endpoints, rank the top 20 most interesting ones
        for further testing based on naming patterns and structure.
        Returns a reordered list (highest priority first).
        """
        if not self.enabled or not endpoints:
            return endpoints

        self.ui.ai(f"AI prioritizing {len(endpoints)} endpoints for testing...")
        system = (
            "You are a bug bounty hunter. Given a list of URLs, select and rank "
            "the TOP 20 most interesting for security testing (IDOR, SQLi, auth bypass, "
            "business logic flaws). Focus on: API endpoints, user/account/admin paths, "
            "endpoints with ID parameters, file operations, payment/billing paths. "
            "Return ONLY a JSON array of the top 20 URLs in priority order."
        )
        # Send a sample to avoid token limits
        sample = endpoints[:80]
        user = f"Endpoints:\n" + "\n".join(sample)
        result = self._call(system, user, max_tokens=800)
        if result:
            try:
                start = result.find("[")
                end   = result.rfind("]") + 1
                if start != -1 and end > start:
                    ranked = json.loads(result[start:end])
                    # Return ranked first, then the rest
                    ranked_set = set(ranked)
                    rest = [e for e in endpoints if e not in ranked_set]
                    return ranked + rest
            except Exception:
                pass
        return endpoints

    # =========================================================================
    # POST-SCAN ANALYSIS
    # =========================================================================

    def analyze_chains(self, target: str, findings: list) -> str | None:
        """Chain analysis after all modules complete."""
        if not findings:
            if self.ui:
                self.ui.info("No findings to chain-analyze.")
            return None

        summary = "\n".join(
            f"- [{f['severity'].upper()}] {f['title']} | {f['url']} | module: {f['module']}"
            for f in findings
        )

        if self.enabled:
            self.ui.ai("Sending findings to NVIDIA AI for chain analysis...")
            system = (
                "You are a world-class bug bounty hunter. "
                "Analyze vulnerability findings and identify: "
                "1) Attack chains where combining findings escalates impact, "
                "2) The single highest-impact attack path with PoC steps, "
                "3) Exploitation priority ranked by bounty value, "
                "4) Estimated bounty range per finding class, "
                "5) Top 3 findings with PoC outlines. "
                "Be concise, technical, and directly actionable."
            )
            user = (
                f"Target: {target}\n\nFindings:\n{summary}\n\n"
                "Identify all chaining opportunities, the highest-impact attack path, "
                "estimated bounty ranges, and top 3 PoC outlines."
            )
            result = self._call(system, user, max_tokens=2000)
            if result:
                self._print_ai(result)
                return result

        # Local fallback
        return self._local_chain_analysis(target, findings)

    def generate_report(self, target: str, findings: list,
                        context: dict) -> str | None:
        """AI-enhanced bug bounty report (optional upgrade over local reporter)."""
        detail = "\n\n".join(
            f"[{f['severity'].upper()}] {f['title']}\n"
            f"URL: {f['url']}\nCVSS: {f.get('cvss','N/A')}\n"
            f"Description: {f['description']}\nRemediation: {f['remediation']}"
            for f in findings
        )
        if self.enabled:
            self.ui.ai("NVIDIA AI generating enhanced bug bounty report...")
            system = (
                "You are an expert bug bounty report writer. "
                "Write professional, detailed, and accurate reports suitable for "
                "HackerOne, Bugcrowd, or direct submission. Include executive summary, "
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
            return self._call(system, user, max_tokens=4000)
        return None

    # =========================================================================
    # API KEY MANAGEMENT HELPERS
    # =========================================================================

    @staticmethod
    def test_key(api_key: str, ui=None) -> bool:
        """
        Send a minimal test request to NVIDIA NIM.
        Returns True if the key works, False otherwise.
        """
        try:
            from openai import OpenAI
            client = OpenAI(base_url=NVIDIA_BASE_URL, api_key=api_key)
            resp = client.chat.completions.create(
                model=NVIDIA_MODEL,
                messages=[{"role": "user", "content": "Say OK"}],
                max_tokens=5,
                temperature=0.6,
                top_p=0.7,
                stream=False,
            )
            answer = resp.choices[0].message.content.strip()
            return bool(answer)
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
            self.ui.subsection("Local Chain Analysis Engine (no AI key set)")

        chains = []
        if has("ssrf") and (has(".env") or has("secret") or has("key")):
            chains.append(("SSRF → Credential Exposure → Cloud Takeover",   "P1 Critical", "$8k–$20k"))
        if has("idor") and has("auth"):
            chains.append(("IDOR + Weak Auth → Mass Data Exfiltration",     "P1/P2",       "$3k–$8k"))
        if has(".env") or has("backup") or has("exposed"):
            chains.append(("Exposed Secrets → Full Application Takeover",   "P1 Critical", "$5k–$15k"))
        if has("graphql") and has("idor"):
            chains.append(("GraphQL Introspection + IDOR → Mutation Abuse", "P2 High",     "$2k–$5k"))
        if has("smuggling") or has("smuggl"):
            chains.append(("HTTP Smuggling → Session Hijacking",            "P1/P2",       "$4k–$12k"))
        if has("xss"):
            chains.append(("XSS → Session Token Theft → Account Takeover",  "P2 High",     "$1k–$4k"))
        if has("cors"):
            chains.append(("CORS Misconfiguration → Cross-Origin Credential Theft", "P2 High", "$1k–$3k"))
        if has("sqli") or has("sql injection"):
            chains.append(("SQL Injection → Database Dump → Full Compromise", "P1 Critical", "$5k–$25k"))

        if self.ui and chains:
            self.ui.blank()
            for name, sev, bounty in chains:
                self.ui.bullet(name)
                self.ui.bullet(f"Severity: {sev}  |  Est. Bounty: {bounty}", indent=8)
                self.ui.blank()
        elif self.ui:
            self.ui.info("No chains detected — focus on individual high-severity findings.")

        # Priority order
        order = ["critical", "high", "medium", "low", "info"]
        sorted_f = sorted(findings, key=lambda f: order.index(f["severity"]))
        if self.ui:
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
