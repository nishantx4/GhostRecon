"""
ScanSession — orchestrates all scan modules, manages findings, triggers AI analysis
"""
import os
import time
import json
from datetime import datetime

import core.config as config
from core.ui import UI, Colors
from core.findings import FindingsDB
from core.ai_engine import AIEngine
from core.baseline import BaselineProfiler, BaselineProfile
from core.tool_runner import ExternalToolRunner

# Phase 1: Recon
from modules.recon      import ReconModule
from modules.cms_scanner import CMSScannerModule
# Phase 2: Configuration & Identity
from modules.headers    import HeadersModule
from modules.subdomain_takeover import SubdomainTakeoverModule
from modules.secrets    import SecretsModule
# Phase 3: Authentication & Authorization
from modules.jwt        import JWTModule
from modules.broken_auth import BrokenAuthModule
from modules.oauth      import OAuthModule
from modules.idor       import IDORModule
# Phase 4: Data & Input Validation
from modules.params     import ParamModule
from modules.js_analysis import JSModule
from modules.file_upload import FileUploadModule
from modules.mass_assignment import MassAssignmentModule
# Phase 5: Injection & Exploitation
from modules.sqli       import SQLiModule
from modules.nosql      import NoSQLModule
from modules.ssti       import SSTIModule
from modules.xss        import XSSModule
from modules.xxe        import XXEModule
from modules.crlf       import CRLFModule
from modules.ssrf       import SSRFModule
from modules.lfi        import LFIModule
from modules.deserialization import DeserializationModule
from modules.prototype_pollution import PrototypePollutionModule
# Phase 6: Client-Side & Logic
from modules.cors       import CORSModule
from modules.csrf       import CSRFModule
from modules.clickjacking import ClickjackingModule
from modules.open_redirect import OpenRedirectModule
from modules.host_header import HostHeaderModule
from modules.websocket  import WebSocketModule
# Phase 7: Advanced
from modules.cache_poisoning import CachePoisoningModule
from modules.smuggling  import SmugglingModule
from modules.rate_limit import RateLimitModule
from modules.graphql    import GraphQLModule
# External Scanners
from modules.nuclei_sim import NucleiModule
# Reporting
from modules.reporter   import ReportModule


MODULE_MAP = {
    'recon':     ReconModule,
    'cms':       CMSScannerModule,
    'headers':   HeadersModule,
    'sub_take':  SubdomainTakeoverModule,
    'secrets':   SecretsModule,
    'jwt':       JWTModule,
    'broken_auth': BrokenAuthModule,
    'oauth':     OAuthModule,
    'idor':      IDORModule,
    'params':    ParamModule,
    'js':        JSModule,
    'upload':    FileUploadModule,
    'mass_assign': MassAssignmentModule,
    'sqli':      SQLiModule,
    'nosql':     NoSQLModule,
    'ssti':      SSTIModule,
    'xss':       XSSModule,
    'xxe':       XXEModule,
    'crlf':      CRLFModule,
    'ssrf':      SSRFModule,
    'lfi':       LFIModule,
    'desync':    DeserializationModule,
    'proto_poll': PrototypePollutionModule,
    'cors':      CORSModule,
    'csrf':      CSRFModule,
    'clickjack': ClickjackingModule,
    'redirect':  OpenRedirectModule,
    'host_header': HostHeaderModule,
    'ws':        WebSocketModule,
    'cache':     CachePoisoningModule,
    'smuggling': SmugglingModule,
    'rate_limit': RateLimitModule,
    'graphql':   GraphQLModule,
    'nuclei':    NucleiModule,
    'report':    ReportModule,
}

# Human-readable labels for every selectable module (used by the TUI's
# module-selection checklist and anywhere else module IDs need a display name).
MODULE_LABELS = {
    'recon':      'Reconnaissance & Crawling',
    'cms':        'CMS Scanner',
    'headers':    'Security Headers',
    'sub_take':   'Subdomain Takeover',
    'secrets':    'Secrets Exposure',
    'jwt':        'JWT Attacks',
    'broken_auth': 'Broken Authentication',
    'oauth':      'OAuth Misconfiguration',
    'idor':       'IDOR',
    'params':     'Parameter Tampering',
    'js':         'JS Analysis',
    'upload':     'File Upload',
    'mass_assign': 'Mass Assignment',
    'sqli':       'SQL Injection',
    'nosql':      'NoSQL Injection',
    'ssti':       'Server-Side Template Injection',
    'xss':        'Cross-Site Scripting',
    'xxe':        'XXE',
    'crlf':       'CRLF Injection',
    'ssrf':       'SSRF',
    'lfi':        'LFI / Path Traversal',
    'desync':     'Deserialization',
    'proto_poll': 'Prototype Pollution',
    'cors':       'CORS Misconfiguration',
    'csrf':       'CSRF',
    'clickjack':  'Clickjacking',
    'redirect':   'Open Redirect',
    'host_header': 'Host Header Injection',
    'ws':         'WebSocket Security',
    'cache':      'Cache Poisoning',
    'smuggling':  'HTTP Request Smuggling',
    'rate_limit': 'Rate Limiting',
    'graphql':    'GraphQL',
    'nuclei':     'Nuclei Scanner',
    'report':     'Report Generation',
}

# Scan presets — single source of truth shared by the CLI (--preset) and the
# TUI's Quick/Standard/Full Profile buttons.
PRESETS = {
    'quick':    ['recon', 'cms', 'headers', 'secrets', 'cors', 'nuclei', 'report'],
    'standard': ['recon', 'cms', 'headers', 'sub_take', 'secrets', 'idor', 'sqli',
                 'xss', 'cors', 'ssrf', 'lfi', 'nuclei', 'report'],
    'full':     list(MODULE_MAP.keys()),
}


def get_preset_modules(preset: str) -> list:
    """Return the module ID list for a named preset (defaults to 'standard')."""
    return list(PRESETS.get(preset, PRESETS['standard']))


class ScanSession:
    def __init__(self, target, api_key=None, modules=None, scope=None,
                 output_dir='./ghostrecon_output', output_file=None,
                 threads=10, timeout=10, delay=0.5, verbose=False, ui=None,
                 event_callback=None, auto_install_tools=True,
                 auth_headers=None, auth_cookies=None):
        self.target     = self._normalize_target(target)
        self.api_key    = api_key
        self.auth_headers = dict(auth_headers or {})
        self.auth_cookies = dict(auth_cookies or {})
        # Default profile: full scan
        # `modules is None` means "not specified" -> default to everything.
        # An explicit `[]` must stay empty, not silently balloon into a full
        # 33-module scan — that's exactly what happened when the interactive
        # CLI's module parser produced an empty list on a typo.
        self.modules    = list(MODULE_MAP.keys()) if modules is None else modules
        self.scope      = scope
        self.output_dir = output_dir
        self.output_file = output_file
        self.threads    = threads
        self.timeout    = timeout
        self.delay      = delay
        self.verbose    = verbose
        self.ui         = ui or UI()
        self.start_time = None
        self.event_callback = event_callback # For TUI updates
        self.auto_install_tools = auto_install_tools
        self.db         = FindingsDB(event_callback=self.event_callback)
        self.context    = {}  # shared data between modules (subdomains, endpoints, etc.)
        self.ai         = AIEngine(api_key=api_key, ui=self.ui, event_callback=self.event_callback)
        self.tool_runner = ExternalToolRunner(self.ui)

    def _ensure_external_tools(self):
        """
        Auto-install the external Go tools the enabled modules actually rely
        on (subfinder/katana/waybackurls for recon, nuclei for the Nuclei
        module). ToolInstaller already implements this — it just was never
        called anywhere, so every scan silently used weak built-in fallbacks
        even when auto-install was documented as a feature.
        """
        if not self.auto_install_tools:
            return
        wanted = []
        if 'recon' in self.modules:
            wanted += ['subfinder', 'katana', 'waybackurls']
        if 'nuclei' in self.modules:
            wanted.append('nuclei')
        wanted = sorted(set(wanted))
        if not wanted:
            return
        try:
            from core.tool_installer import ToolInstaller
            installer = ToolInstaller(self.ui)
            missing = [t for t in wanted if not installer.is_installed(t)]
            if missing:
                self.ui.info(f"Auto-installing external tools: {', '.join(missing)} ...")
                installer.ensure_tools(missing)
        except Exception as e:
            self.ui.warn(f"Tool auto-install skipped: {e}")

    def _normalize_target(self, t):
        t = t.strip().lower()
        for prefix in ('https://', 'http://'):
            if t.startswith(prefix):
                t = t[len(prefix):]
        return t.rstrip('/')
        
    def _emit(self, event_type, data):
        """Emit an event to the TUI if event_callback is provided."""
        if self.event_callback:
            try:
                self.event_callback(event_type, data)
            except Exception:
                pass

    def run(self):
        self.start_time = time.time()
        os.makedirs(self.output_dir, exist_ok=True)

        self._emit("scan_started", {"target": self.target, "modules": self.modules})

        # Seed any user-supplied auth (--header/--cookie) before anything
        # runs. Every module also checks/adds to this: recon.py adds static
        # OpenAPI example headers (without overwriting these), and modules
        # that find a live credential (e.g. sqli.py's auth-bypass capture)
        # add to it too — so a scan that starts authenticated stays
        # authenticated, and a scan that starts blind can become
        # authenticated mid-run.
        if self.auth_headers:
            self.context['auth_headers'] = dict(self.auth_headers)
        if self.auth_cookies:
            self.context['auth_cookies'] = dict(self.auth_cookies)

        self.ui.section(f"Starting GhostRecon against: {self.target}")
        self.ui.info(f"Modules: {len(self.modules)} enabled")
        self.ui.info(f"AI Analysis: {'Enabled — NVIDIA NIM (' + config.get_model() + ')' if self.api_key else 'Local engine (no API key set)'}")
        if self.auth_headers or self.auth_cookies:
            self.ui.info(f"Auth context: {len(self.auth_headers)} header(s), {len(self.auth_cookies)} cookie(s) supplied")
        self.ui.blank()

        # ── External tool auto-install (subfinder/katana/waybackurls/nuclei) ──
        self._ensure_external_tools()

        # ── Target Profiling (Baseline) ──
        self._emit("phase_started", {"name": "Target Profiling"})
        self.ui.section("Phase 0: Target Profiling & Fingerprinting")
        baseline = BaselineProfiler(self.target, timeout=self.timeout, ui=self.ui)
        profile = baseline.profile()
        self.context['baseline_profile'] = profile
        self._emit("profiling_complete", profile)

        # ── Run modules in order ──
        total_mods = len([m for m in self.modules if m in MODULE_MAP and m != 'report'])
        done = 0
        for mod_name in self.modules:
            if mod_name not in MODULE_MAP:
                self.ui.warn(f"Unknown module '{mod_name}' — skipping")
                continue
                
            self._emit("module_started", {"module": mod_name})
            
            try:
                ModClass = MODULE_MAP[mod_name]
                mod = ModClass(
                    target=self.target,
                    db=self.db,
                    ui=self.ui,
                    context=self.context,
                    timeout=self.timeout,
                    delay=self.delay,
                    threads=self.threads,
                    verbose=self.verbose,
                    ai=self.ai,
                    output_dir=self.output_dir,
                )
                
                # Pass event callback down if module supports it
                if hasattr(mod, 'event_callback'):
                    mod.event_callback = self.event_callback
                    
                mod.run()
                
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.ui.error(f"Module '{mod_name}' crashed: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                self._emit("module_failed", {"module": mod_name, "error": str(e)})
                continue
                
            self._emit("module_completed", {"module": mod_name})

        # ── AI Chain Analysis ──
        self._run_ai_chain_analysis()

        # ── Final summary ──
        self._print_summary()
        self._save_results()
        self._emit("scan_completed", {"duration": time.time() - self.start_time, "findings": len(self.db.findings)})

    def _run_ai_chain_analysis(self):
        if not self.db.findings:
            return
        self.ui.section("AI Vulnerability Chain Analysis")
        self._emit("phase_started", {"name": "AI Chain Analysis"})
        self.ai.analyze_chains(self.target, self.db.findings)

    def _print_summary(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)

        self.ui.section("Scan Complete — Summary")
        self.ui.info(f"Target: {self.target}")
        self.ui.info(f"Duration: {mins}m {secs}s")
        self.ui.blank()

        counts = self.db.severity_counts()
        self.ui.sev_bar(counts)
        self.ui.blank()

        # Weighted risk score (0-100) to give an at-a-glance posture.
        weights = {'critical': 40, 'high': 20, 'medium': 8, 'low': 3, 'info': 0}
        raw = sum(weights.get(s, 0) * counts.get(s, 0) for s in weights)
        risk = min(100, raw)
        grade = ('CRITICAL' if risk >= 80 else 'HIGH' if risk >= 50 else
                 'MODERATE' if risk >= 20 else 'LOW' if risk > 0 else 'CLEAN')
        self.ui.panel("Risk Posture", [
            f"Risk score : {risk}/100  ({grade})",
            f"Findings   : {len(self.db.findings)} total",
        ])
        self.ui.blank()

        # Top findings
        critical = [f for f in self.db.findings if f['severity'] == 'critical']
        high     = [f for f in self.db.findings if f['severity'] == 'high']
        top = (critical + high)[:10]
        if top:
            self.ui.subsection("Top Findings")
            for i, f in enumerate(top, 1):
                self.ui.find(f['severity'], f['title'], f.get('url',''))

        self.ui.blank()
        self.ui.info(f"Total findings: {len(self.db.findings)}")
        subdomains = self.context.get('subdomains', [])
        endpoints  = self.context.get('endpoints', [])
        self.ui.info(f"Subdomains: {len(subdomains)}  |  Endpoints: {len(endpoints)}")

    def _save_results(self):
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Sanitize filename — Windows forbids : / \ * ? " < > | in filenames
        base = self.target
        for ch in (':', '/', '\\', '*', '?', '"', '<', '>', '|'):
            base = base.replace(ch, '_')

        # JSON raw data
        json_path = os.path.join(self.output_dir, f"ghostrecon_{base}_{ts}.json")
        data = {
            'meta': {
                'target': self.target,
                'scan_time': datetime.now().isoformat(),
                'modules': self.modules,
                'scope': self.scope,
            },
            'subdomains': self.context.get('subdomains', []),
            'endpoints':  self.context.get('endpoints', []),
            'js_secrets': self.context.get('js_secrets', []),
            'commands':   self.context.get('commands', []),
            'findings':   self.db.findings,
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.ui.ok(f"JSON saved: {json_path}")

        # Markdown report
        md_path = self.output_file or os.path.join(self.output_dir, f"ghostrecon_{base}_{ts}.md")
        report_mod = ReportModule(
            target=self.target, db=self.db, ui=self.ui,
            context=self.context, timeout=self.timeout,
            delay=self.delay, threads=self.threads,
            verbose=self.verbose, ai=self.ai,
            output_dir=self.output_dir,
        )
        md = report_mod.build_report()
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(md)
        self.ui.ok(f"Report saved: {md_path}")

        # Commands runbook
        cmds = self.context.get('commands', [])
        if cmds:
            cmd_path = os.path.join(self.output_dir, f"ghostrecon_{base}_{ts}_commands.sh")
            with open(cmd_path, 'w', encoding='utf-8') as f:
                f.write(f"#!/bin/bash\n# GhostRecon Command Runbook — {self.target}\n# Generated: {datetime.now().isoformat()}\n\n")
                f.write('\n'.join(cmds))
            self.ui.ok(f"Command runbook saved: {cmd_path}")

    def save_partial(self):
        """Called on KeyboardInterrupt to preserve what we have"""
        self.ui.warn("Saving partial scan data...")
        self._save_results()