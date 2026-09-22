from textual.screen import Screen
from textual.widgets import Label, Static
from textual.app import ComposeResult
from textual.screen import Screen
from textual.containers import ScrollableContainer

from tui.widgets.scan_progress import ScanProgress
from tui.widgets.finding_panel import FindingPanel

class DashboardScreen(Screen):
    """Main dashboard screen during scan."""
    def compose(self) -> ComposeResult:
        yield ScanProgress(id="progress_panel")
        yield ScrollableContainer(id="tool_execution_panel")
        yield FindingPanel(id="finding_panel")
