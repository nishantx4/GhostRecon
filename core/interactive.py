import os

from core.ui import Colors

DEFAULT_MODULES = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss',
                    'idor', 'cors', 'ssrf', 'redirect', 'report']


class InteractiveMenu:
    def __init__(self, ui):
        self.ui = ui
        self.target = None
        self.modules = []

    def run(self):
        self.ui.section("Interactive Mode — GhostRecon v3")

        # 1. Get Target
        while not self.target:
            self.target = input(f"{self.ui.c(Colors.BOLD, '  [?] Enter Target (e.g. example.com): ')}").strip()

        # 2. Select Modules
        self.ui.subsection("Available Modules")
        available = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss', 'idor',
                     'sqli', 'graphql', 'smuggling', 'cors', 'ssrf', 'ssti',
                     'redirect', 'secrets', 'report']
        for i, m in enumerate(available, 1):
            print(f"    {i}. {m}")

        selection = input(
            f"\n{self.ui.c(Colors.BOLD, '  [?] Enter module numbers or names (comma-separated) or leave blank for default: ')}"
        ).strip()

        if not selection:
            self.modules = list(DEFAULT_MODULES)
        else:
            chosen = []
            for tok in selection.split(','):
                tok = tok.strip()
                if not tok:
                    continue
                if tok.isdigit() and 1 <= int(tok) <= len(available):
                    chosen.append(available[int(tok) - 1])
                elif tok.lower() in available:
                    chosen.append(tok.lower())
                else:
                    self.ui.warn(f"Unknown module '{tok}' — skipping")

            seen = set()
            self.modules = [m for m in chosen if not (m in seen or seen.add(m))]
            if self.modules and 'report' not in self.modules:
                self.modules.append('report')
            if not self.modules:
                self.ui.warn("No valid modules selected — using default set")
                self.modules = list(DEFAULT_MODULES)

        # 3. Confirmation
        self.ui.ok(f"Starting scan on {self.ui.c(Colors.CYAN, self.target)}")
        self.ui.info(f"Modules: {', '.join(self.modules)}")

        # Launching via Session (this logic is handled back in ghostrecon.py)
        return self.target, self.modules