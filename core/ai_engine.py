"""
AIEngine — wraps Anthropic API for vuln chain analysis, logic flaw detection, and report writing.
Falls back to a local rule-based engine when no API key is provided.
"""
import json


class AIEngine:
    def __init__(self, api_key=None, ui=None):
        self.api_key = api_key
        self.ui = ui
        self._client = None
        if api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
            except ImportError:
                self.ui.warn("anthropic package not installed. Run: pip install anthropic")
                self._client = None

    def _call(self, system_prompt, user_prompt, max_tokens=2000):
        if not self._client:
            return None
        try:
            msg = self._client.messages.create(
                model="claude-opus-4-5",
                max_tokens=max_tokens,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}]
            )
            return msg.content[0].text
        except Exception as e:
            self.ui.error(f"Claude API error: {e}")
            return None

    # ─────────────────────────────────────────────────────
    # PUBLIC API
    # ─────────────────────────────────────────────────────

    def analyze_chains(self, target, findings):
        """Analyze vulnerability chains and attack paths"""
        if not findings:
            self.ui.info("No findings to analyze.")
            return

        summary = '\n'.join(
            f"- [{f['severity'].upper()}] {f['title']} | URL: {f['url']} | Module: {f['module']}"
            for f in findings
        )

        if self._client:
            self.ui.ai("Sending findings to Claude for chain analysis...")
            system = (
                "You are a world-class bug bounty hunter and penetration tester. "
                "Analyze vulnerability findings and identify: "
                "1) Attack chains where combining findings escalates impact, "
                "2) Business logic flaws implied by the attack surface, "
                "3) Exploitation priority ranked by bounty value, "
                "4) CVSS-based remediation order, "
                "5) PoC steps for top 3 findings. "
                "Be concise, technical, and directly actionable. No fluff."
            )
            user = (
                f"Target: {target}\n\nFindings:\n{summary}\n\n"
                "Identify all chaining opportunities, the single highest-impact attack path, "
                "estimated bounty ranges per finding, and the top 3 PoC outlines."
            )
            result = self._call(system, user, max_tokens=2500)
            if result:
                self.ui.blank()
                for line in result.split('\n'):
                    self.ui.raw(f"    {line}")
                self.ui.blank()
                return result
        # Fallback
        return self._local_chain_analysis(target, findings)

    def generate_report(self, target, findings, context):
        """Generate a professional bug bounty report"""
        detail = '\n\n'.join(
            f"[{f['severity'].upper()}] {f['title']}\n"
            f"URL: {f['url']}\nCVSS: {f.get('cvss','N/A')}\n"
            f"Description: {f['description']}\nRemediation: {f['remediation']}"
            for f in findings
        )

        if self._client:
            self.ui.ai("Generating AI-enhanced bug bounty report...")
            system = (
                "You are an expert bug bounty report writer. "
                "Write professional, detailed, and accurate reports suitable for HackerOne, Bugcrowd, or direct submission. "
                "Include executive summary, severity breakdown, full technical details per finding, "
                "impact analysis, PoC steps, and remediation priority matrix."
            )
            user = (
                f"Target: {target}\n"
                f"Subdomains found: {len(context.get('subdomains', []))}\n"
                f"Endpoints discovered: {len(context.get('endpoints', []))}\n\n"
                f"Findings:\n{detail}\n\n"
                "Write a complete, professional bug bounty report in Markdown."
            )
            result = self._call(system, user, max_tokens=4000)
            if result:
                return result

        # Fallback
        from modules.reporter import ReportModule
        return None  # Reporter will use its own local builder

    def suggest_next_steps(self, target, findings, context):
        """Suggest what to test next based on discovered attack surface"""
        endpoints = context.get('endpoints', [])
        tech = context.get('tech_stack', [])

        if self._client:
            self.ui.ai("AI generating next-step recommendations...")
            system = (
                "You are a senior bug bounty hunter. "
                "Based on the recon data, suggest specific, targeted follow-up tests. "
                "Reference real tools (Burp Suite, nuclei, ffuf, sqlmap, etc.) and exact payloads/techniques."
            )
            user = (
                f"Target: {target}\n"
                f"Tech stack detected: {', '.join(tech) if tech else 'Unknown'}\n"
                f"Sample endpoints: {chr(10).join(endpoints[:20])}\n"
                f"Current findings: {chr(10).join(f['title'] for f in findings[:10])}\n\n"
                "What are the 5 most promising next tests? Be specific and technical."
            )
            result = self._call(system, user, max_tokens=1500)
            if result:
                self.ui.blank()
                self.ui.subsection("AI-Recommended Next Steps")
                for line in result.split('\n'):
                    self.ui.raw(f"    {line}")
                return result
        return None

    # ─────────────────────────────────────────────────────
    # LOCAL FALLBACK ENGINE
    # ─────────────────────────────────────────────────────

    def _local_chain_analysis(self, target, findings):
        def has(kw):
            return any(kw.lower() in f['title'].lower() or kw.lower() in f.get('description','').lower()
                      for f in findings)
        def by_sev(s):
            return [f for f in findings if f['severity'] == s]

        self.ui.subsection("Local Chain Analysis Engine")
        chains = []

        if has('ssrf') and (has('.env') or has('secret') or has('key')):
            chains.append(('SSRF → Credential Exposure → Cloud Takeover', 'P1 Critical', '$8k–$20k'))
        if has('idor') and has('auth'):
            chains.append(('IDOR + Weak Auth → Mass Data Exfiltration', 'P1/P2', '$3k–$8k'))
        if has('.env') or has('backup') or has('exposed'):
            chains.append(('Exposed Secrets → Full Application Takeover', 'P1 Critical', '$5k–$15k'))
        if has('graphql') and has('idor'):
            chains.append(('GraphQL Introspection + IDOR → Hidden Mutation Abuse', 'P2 High', '$2k–$5k'))
        if has('smuggling') or has('smuggl'):
            chains.append(('HTTP Request Smuggling → Session Hijacking', 'P1/P2', '$4k–$12k'))
        if has('xss'):
            chains.append(('XSS → Session Token Theft → Account Takeover', 'P2 High', '$1k–$4k'))
        if has('cors'):
            chains.append(('CORS Misconfiguration → Cross-Origin Credential Theft', 'P2 High', '$1k–$3k'))
        if has('sqli') or has('sql injection'):
            chains.append(('SQL Injection → Database Dump → Full Compromise', 'P1 Critical', '$5k–$25k'))

        if chains:
            self.ui.blank()
            for name, sev, bounty in chains:
                self.ui.bullet(f"{self.ui.c(Colors_ref.PINK, name)}")
                self.ui.bullet(f"Severity: {sev}  |  Est. Bounty: {bounty}", indent=8)
                self.ui.blank()
        else:
            self.ui.info("No direct chains detected — focus on individual high-severity findings.")

        # Priority
        order = ['critical','high','medium','low','info']
        sorted_f = sorted(findings, key=lambda f: order.index(f['severity']))
        self.ui.blank()
        self.ui.subsection("Priority Order")
        bounty_map = {'critical':'$3k–$15k','high':'$1k–$5k','medium':'$200–$1k','low':'$50–$200','info':'$0–$50'}
        for i, f in enumerate(sorted_f[:8], 1):
            self.ui.bullet(
                f"#{i} [{f['severity'].upper()}] {f['title']}  —  Est. {bounty_map.get(f['severity'],'N/A')}",
                indent=4
            )


# Lazy import to avoid circular
try:
    from core.ui import Colors as Colors_ref
except Exception:
    class Colors_ref:
        PINK = ''
