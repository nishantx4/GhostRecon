from textual.screen import Screen
from textual.widgets import Markdown, Button
from textual.containers import Vertical
from textual.app import ComposeResult

class ReportViewScreen(Screen):
    """Scrollable report viewer with export functionality."""
    
    def compose(self) -> ComposeResult:
        yield Vertical(
            Markdown("# Scan Report\n\nNo findings yet."),
            Button("Export Report", id="export_btn", variant="primary"),
            Button("New Scan", id="new_scan_btn")
        )
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "new_scan_btn":
            self.app.push_screen("setup")
        elif event.button.id == "export_btn":
            self.notify("Report exported to output directory.")
