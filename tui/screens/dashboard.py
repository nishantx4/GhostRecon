from textual.screen import Screen
from textual.widgets import Static
from textual.app import ComposeResult
from textual.containers import ScrollableContainer

from tui.widgets.scan_info_bar import ScanInfoBar
from tui.widgets.scan_progress import ScanProgress
from tui.widgets.finding_panel import FindingPanel
from tui.widgets.ai_analysis_panel import AIAnalysisPanel


class DashboardScreen(Screen):
    """Main dashboard screen during scan — 3×3 layout."""

    def compose(self) -> ComposeResult:
        yield ScanInfoBar(id="info_bar")
        yield ScanProgress(id="progress_panel")
        yield ScrollableContainer(
            Static("TOOL OUTPUT", classes="panel-title"),
            id="tool_execution_panel",
        )
        yield AIAnalysisPanel(id="ai_panel")
        yield FindingPanel(id="finding_panel")
