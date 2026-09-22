from textual.widgets import Static
from textual.app import ComposeResult
from textual.reactive import reactive

class SeverityChart(Static):
    """Dynamic horizontal bar chart for severity breakdown."""
    
    def compose(self) -> ComposeResult:
        self.text_widget = Static("Severity Summary: [red]Critical: 0[/] | [orange1]High: 0[/] | [yellow]Medium: 0[/] | [cyan]Low: 0[/]", id="severity_chart_text")
        yield self.text_widget
        
    def update_counts(self, critical, high, medium, low):
        self.text_widget.update(f"Severity Summary: [red]Critical: {critical}[/] | [orange1]High: {high}[/] | [yellow]Medium: {medium}[/] | [cyan]Low: {low}[/]")
