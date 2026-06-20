"""
ScanSession — orchestrates all scan modules, manages findings, triggers AI analysis
"""
import os
import time
import json
from datetime import datetime

from core.ui import UI, Colors
from core.findings import FindingsDB
from core.ai_engine import AIEngine
from modules.recon      import ReconModule
from modules.headers    import HeadersModule
from modules.js_analysis import JSModule
from modules.params     import ParamModule
from modules.nuclei_sim import NucleiModule
from modules.xss        import XSSModule
from modules.idor       import IDORModule
from modules.sqli       import SQLiModule
from modules.graphql    import GraphQLModule
from modules.smuggling  import SmugglingModule
from modules.cors       import CORSModule
from modules.ssrf       import SSRFModule
from modules.secrets    import SecretsModule
from modules.ssti       import SSTIModule
from modules.open_redirect import OpenRedirectModule
from modules.reporter   import ReportModule


MODULE_MAP = {
    'recon':     ReconModule,
    'headers':   HeadersModule,
    'js':        JSModule,
    'params':    ParamModule,
    'nuclei':    NucleiModule,
    'xss':       XSSModule,
    'idor':      IDORModule,
    'sqli':      SQLiModule,
    'graphql':   GraphQLModule,
    'smuggling': SmugglingModule,
    'cors':      CORSModule,
    'ssrf':      SSRFModule,
    'ssti':      SSTIModule,
    'redirect':  OpenRedirectModule,
    'secrets':   SecretsModule,
    'report':    ReportModule,
}


class ScanSession:
    def __init__(self, target, api_key=None, modules=None, scope=None,
                 output_dir='./ghostrecon_output', output_file=None,
                 threads=10, timeout=10, delay=0.5, verbose=False, ui=None):
        self.target     = self._normalize_target(target)
        self.api_key    = api_key
        self.modules    = modules or ['recon','headers','js','params','nuclei','xss','idor','cors','ssrf','redirect','report']
        self.scope      = scope
        self.output_dir = output_dir
        self.output_file = output_file
        self.threads    = threads
        self.timeout    = timeout
        self.delay      = delay
        self.verbose    = verbose
        self.ui         = ui or UI()
        self.start_time = None
        self.db         = FindingsDB()
        self.ai         = AIEngine(api_key=api_key, ui=self.ui)
        self.context    = {}  # shared data between modules (subdomains, endpoints, etc.)

    def _normalize_target(self, t):
        t = t.strip().lower()
        for prefix in ('https://', 'http://'):
            if t.startswith(prefix):
                t = t[len(prefix):]
        return t.rstrip('/')

    def run(self):
        self.start_time = time.time()
        os.makedirs(self.output_dir, exist_ok=True)

        self.ui.section(f"Starting GhostRecon against: {self.target}")
        self.ui.panel("Scan Configuration", [
            f"Target   : {self.target}",
            f"Modules  : {', '.join(self.modules)}",
            f"Scope    : {self.scope or 'all discovered assets in-scope'}",
            f"AI       : {'NVIDIA NIM (enabled)' if self.api_key else 'local engine (no key)'}",
            f"Threads  : {self.threads}  |  Delay: {self.delay}s  |  Timeout: {self.timeout}s",
            f"Output   : {self.output_dir}",
        ])
        self.ui.blank()

        # ── Run modules in order ──
        total_mods = len([m for m in self.modules if m in MODULE_MAP and m != 'report'])
        done = 0
        for mod_name in self.modules:
            if mod_name not in MODULE_MAP:
                self.ui.warn(f"Unknown module '{mod_name}' — skipping")
                continue
            if mod_name != 'report':
                done += 1
                self.ui.info(f"[{done}/{total_mods}] running module: {mod_name}")
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
                mod.run()
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.ui.error(f"Module '{mod_name}' crashed: {e}")
                if self.verbose:
                    import traceback
                    traceback.print_exc()
                continue

        # ── AI Chain Analysis ──
        self._run_ai_chain_analysis()

        # ── Final summary ──
        self._print_summary()
        self._save_results()

    def _run_ai_chain_analysis(self):
        if not self.db.findings:
            return
        self.ui.section("AI Vulnerability Chain Analysis")
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