from textual.widgets import Static, ProgressBar
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

from tui.theme import ACCENT, CRIT


class ScanProgress(Static):
    """Compact module progress tracker."""

    def compose(self) -> ComposeResult:
        yield Static("MODULES", classes="panel-title")
        self.module_list = VerticalScroll(id="module_list")
        yield self.module_list
        self._count_label = Static("0/0 complete", id="module_count_label", classes="module-count")
        yield self._count_label
        self.progress = ProgressBar(total=100, show_eta=False, id="scan_progress_bar")
        yield self.progress

    def init_modules(self, modules):
        self.module_list.remove_children()
        self.module_status = {}
        for mod in modules:
            label = Static(f"[ ] {mod}", classes="module-pending", id=f"mod_{mod}", markup=True)
            self.module_list.mount(label)
            self.module_status[mod] = "pending"

        self.total_modules = len(modules)
        self.completed_modules = 0
        self.progress.total = self.total_modules
        self.progress.progress = 0
        self._update_count()

    def start_module(self, mod_name):
        if mod_name in self.module_status:
            self.module_status[mod_name] = "running"
            try:
                label = self.module_list.query_one(f"#mod_{mod_name}", Static)
                label.update(f"[{ACCENT}]>[/{ACCENT}] {mod_name}")
                label.classes = "module-running"
            except Exception:
                pass

    def complete_module(self, mod_name):
        if mod_name in self.module_status:
            self.module_status[mod_name] = "complete"
            try:
                label = self.module_list.query_one(f"#mod_{mod_name}", Static)
                label.update(f"[x] {mod_name}")
                label.classes = "module-complete"
            except Exception:
                pass
            self.completed_modules += 1
            self.progress.progress = self.completed_modules
            self._update_count()

    def fail_module(self, mod_name, error=""):
        if mod_name in self.module_status:
            self.module_status[mod_name] = "failed"
            try:
                label = self.module_list.query_one(f"#mod_{mod_name}", Static)
                label.update(f"[{CRIT}]![/{CRIT}] {mod_name}")
                label.classes = "module-failed"
            except Exception:
                pass
            self.completed_modules += 1
            self.progress.progress = self.completed_modules
            self._update_count()

    def _update_count(self):
        total = getattr(self, "total_modules", 0)
        done = getattr(self, "completed_modules", 0)
        try:
            self._count_label.update(f"{done}/{total} complete")
        except Exception:
            pass
