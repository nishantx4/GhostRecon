from textual.widgets import Static
from textual.containers import VerticalScroll
from textual.app import ComposeResult
from textual.reactive import reactive

from tui.theme import SEVERITY


class FindingPanel(Static):
    """Widget showing live findings as they arrive — richer card layout."""

    finding_count = reactive(0)

    def compose(self) -> ComposeResult:
        yield Static("FINDINGS", classes="panel-title")
        self.counter_widget = Static(
            self._counts_markup(0, 0, 0, 0),
            id="finding_counter",
            markup=True,
        )
        yield self.counter_widget
        yield VerticalScroll(id="finding_list")

    def add_finding(self, title: str, severity: str, url: str, confidence: str,
                    module: str = "", description: str = ""):
        self.finding_count += 1

        sev = severity.upper()
        color = SEVERITY.get(severity.lower(), SEVERITY["info"])

        lines = [f"[{color}][{sev}][/{color}] {title}"]
        if url:
            lines.append(f"  ↳ {url}")
        meta_parts = []
        if module:
            meta_parts.append(f"module:{module}")
        if confidence:
            meta_parts.append(f"conf:{confidence}")
        if meta_parts:
            lines.append(f"  {' │ '.join(meta_parts)}")
        if description:
            desc = description[:120] + ("…" if len(description) > 120 else "")
            lines.append(f"  {desc}")

        card_text = "\n".join(lines)
        finding_widget = Static(
            card_text, classes=f"finding-item finding-{severity.lower()}", markup=True
        )
        self.query_one("#finding_list").mount(finding_widget)

    def update_counts(self, critical, high, medium, low):
        self.counter_widget.update(self._counts_markup(critical, high, medium, low))

    @staticmethod
    def _counts_markup(critical, high, medium, low) -> str:
        c, h, m, lo = SEVERITY["critical"], SEVERITY["high"], SEVERITY["medium"], SEVERITY["low"]
        return (
            f"[{c}]CRIT {critical}[/{c}]  [{h}]HIGH {high}[/{h}]  "
            f"[{m}]MED {medium}[/{m}]  [{lo}]LOW {low}[/{lo}]"
        )
