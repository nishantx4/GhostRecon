from textual.widgets import Static, ProgressBar
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

class ScanProgress(Static):
    """Module progress tracker."""
    
    def compose(self) -> ComposeResult:
        yield Static("Module Progress", classes="panel-title")
        self.module_list = VerticalScroll(id="module_list")
        yield self.module_list
        self.progress = ProgressBar(total=100, show_eta=False, id="scan_progress_bar")
        yield self.progress
        
    def init_modules(self, modules):
        self.module_list.remove_children()
        self.module_status = {}
        for mod in modules:
            label = Static(f"⏳ {mod}", classes="module-pending", id=f"mod_{mod}")
            self.module_list.mount(label)
            self.module_status[mod] = "pending"
            
        self.total_modules = len(modules)
        self.completed_modules = 0
        self.progress.total = self.total_modules
        self.progress.progress = 0

    def start_module(self, mod_name):
        if mod_name in self.module_status:
            self.module_status[mod_name] = "running"
            label = self.module_list.query_one(f"#mod_{mod_name}", Static)
            label.update(f"⚡ {mod_name}")
            label.classes = "module-running"

    def complete_module(self, mod_name):
        if mod_name in self.module_status:
            self.module_status[mod_name] = "complete"
            label = self.module_list.query_one(f"#mod_{mod_name}", Static)
            label.update(f"✅ {mod_name}")
            label.classes = "module-complete"
            self.completed_modules += 1
            self.progress.progress = self.completed_modules
