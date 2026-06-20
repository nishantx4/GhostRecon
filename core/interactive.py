import os

class InteractiveMenu:
    def __init__(self, ui):
        self.ui = ui
        self.target = None
        self.modules = []

    def run(self):
        self.ui.section("Interactive Mode — GhostRecon v3")
        
        # 1. Get Target
        while not self.target:
            self.target = input(f"{self.ui.c('BOLD', '  [?] Enter Target (e.g. example.com): ')}").strip()
        
        # 2. Select Modules
        self.ui.subsection("Available Modules")
        available = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss', 'idor',
                     'sqli', 'graphql', 'smuggling', 'cors', 'ssrf', 'ssti',
                     'redirect', 'secrets', 'report']
        for i, m in enumerate(available, 1):
            print(f"    {i}. {m}")
        
        selection = input(f"\n{self.ui.c('BOLD', '  [?] Enter modules (comma-separated) or leave blank for default: ')}").strip()
        
        if not selection:
            self.modules = ['recon', 'headers', 'js', 'params', 'nuclei', 'xss',
                            'idor', 'cors', 'ssrf', 'redirect', 'report']
        else:
            self.modules = [available[int(i)-1] for i in selection.split(',') if i.isdigit() and int(i) <= len(available)]

        # 3. Confirmation
        self.ui.ok(f"Starting scan on {self.ui.c('CYAN', self.target)}")
        self.ui.info(f"Modules: {', '.join(self.modules)}")
        
        # Launching via Session (this logic is handled back in ghostrecon.py)
        return self.target, self.modules