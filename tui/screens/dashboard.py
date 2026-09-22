from textual.screen import Screen
from textual.widgets import Label, Static
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.app import ComposeResult
from tui.widgets.scan_progress import ScanProgress
from tui.widgets.finding_panel import FindingPanel
from tui.widgets.severity_chart import SeverityChart

class DashboardScreen(Screen):
    """Main dashboard screen during scan."""
    def compose(self) -> ComposeResult:
        yield ScanProgress(id="progress_panel")
        yield ScrollableContainer(id="tool_execution_panel")
        yield FindingPanel(id="finding_panel")
        yield SeverityChart(id="severity_chart")
