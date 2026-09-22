from textual.widgets import Static
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

class FindingPanel(Static):
    """Widget showing live findings as they arrive."""
    
    finding_count = reactive(0)

    def compose(self) -> ComposeResult:
        yield Static("Live Findings", classes="panel-title")
        yield Static("🔴 0 Critical  🟠 0 High  🟡 0 Medium", id="finding_counter")
        yield VerticalScroll(id="finding_list")

    def add_finding(self, title: str, severity: str, url: str, confidence: str):
        self.finding_count += 1
        finding_widget = Static(f"[{severity}] {title}\nURL: {url}\nConfidence: {confidence}", classes="finding-item")
        self.query_one("#finding_list").mount(finding_widget)
        # Update counter logic would go here
