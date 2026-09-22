from textual.widgets import Static
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

class FindingPanel(Static):
    """Widget showing live findings as they arrive."""
    
    finding_count = reactive(0)

    def compose(self) -> ComposeResult:
        yield Static("Live Findings", classes="panel-title")
        self.counter_widget = Static("🔴 0 Critical  🟠 0 High  🟡 0 Medium  🔵 0 Low", id="finding_counter")
        yield self.counter_widget
        yield VerticalScroll(id="finding_list")

    def add_finding(self, title: str, severity: str, url: str, confidence: str):
        self.finding_count += 1
        finding_widget = Static(f"[{severity.upper()}] {title} | {url} | Conf: {confidence}", classes="finding-item")
        self.query_one("#finding_list").mount(finding_widget)

    def update_counts(self, critical, high, medium, low):
        self.counter_widget.update(
            f"🔴 {critical} Critical  🟠 {high} High  🟡 {medium} Medium  🔵 {low} Low"
        )
