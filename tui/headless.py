from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress

class HeadlessRenderer:
    """Rich-only headless renderer for --no-tui mode using Rich Console."""
    
    def __init__(self):
        self.console = Console()
        self.progress = Progress(console=self.console)
        
    def render_target_info(self, target: str, threads: int):
        panel = Panel(f"Target: {target}\nThreads: {threads}", title="Scan Config", border_style="cyan")
        self.console.print(panel)
        
    def log_tool_execution(self, command: str):
        self.console.print(f"[bold yellow][⚡ RUNNING][/bold yellow] {command}")
        
    def log_finding(self, title: str, severity: str, url: str):
        color = "red" if severity.lower() == "critical" else ("yellow" if severity.lower() == "medium" else "orange1")
        self.console.print(f"[{color}][{severity}][/{color}] {title} - {url}")

    def render_summary(self, findings_count: int):
        table = Table(title="Scan Summary")
        table.add_column("Severity", justify="right", style="cyan")
        table.add_column("Count", justify="right", style="magenta")
        table.add_row("Total", str(findings_count))
        self.console.print(table)
