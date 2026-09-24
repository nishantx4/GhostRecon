"""
ScanInfoBar — compact top bar showing live scan metadata.
"""
import time
from textual.widgets import Static
from textual.containers import Horizontal
from textual.app import ComposeResult
from textual.reactive import reactive

from tui.theme import ACCENT, TEXT_DIM, CRIT, HIGH, MED, LOW


class ScanInfoBar(Static):
    """Horizontal info bar: target, elapsed time, module progress, AI status, findings."""

    target_name = reactive("—")
    elapsed = reactive(0.0)
    modules_done = reactive(0)
    modules_total = reactive(0)
    ai_active = reactive(False)
    finding_counts = reactive({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})

    def compose(self) -> ComposeResult:
        yield Horizontal(
            Static("", id="info_target", classes="info-cell", markup=True),
            Static("", id="info_time", classes="info-cell", markup=True),
            Static("", id="info_modules", classes="info-cell", markup=True),
            Static("", id="info_ai", classes="info-cell", markup=True),
            Static("", id="info_findings", classes="info-cell", markup=True),
            id="info_bar_row",
        )

    def on_mount(self) -> None:
        self._refresh_all()
        self.set_interval(1.0, self._tick_timer)

    # ── Timer tick ──
    def _tick_timer(self) -> None:
        if self._start_time is not None:
            self.elapsed = time.time() - self._start_time

    _start_time: float | None = None

    def start_timer(self) -> None:
        self._start_time = time.time()

    def stop_timer(self) -> None:
        if self._start_time is not None:
            self.elapsed = time.time() - self._start_time

    # ── Watchers ──
    def watch_target_name(self, value: str) -> None:
        self._update_cell("info_target", f"[{TEXT_DIM}]TARGET[/{TEXT_DIM}]  {value}")

    def watch_elapsed(self, value: float) -> None:
        m, s = divmod(int(value), 60)
        self._update_cell("info_time", f"[{TEXT_DIM}]ELAPSED[/{TEXT_DIM}]  {m:02d}:{s:02d}")

    def watch_modules_done(self, value: int) -> None:
        self._refresh_modules()

    def watch_modules_total(self, value: int) -> None:
        self._refresh_modules()

    def watch_ai_active(self, value: bool) -> None:
        if value:
            label = f"[{ACCENT}]●[/{ACCENT}] AI ACTIVE"
        else:
            label = f"[{TEXT_DIM}]○ LOCAL ONLY[/{TEXT_DIM}]"
        self._update_cell("info_ai", label)

    def watch_finding_counts(self, value: dict) -> None:
        c = value.get("critical", 0)
        h = value.get("high", 0)
        m = value.get("medium", 0)
        lo = value.get("low", 0)
        total = c + h + m + lo + value.get("info", 0)
        self._update_cell(
            "info_findings",
            f"[{TEXT_DIM}]FINDINGS[/{TEXT_DIM}] {total}  "
            f"[{CRIT}]C:{c}[/{CRIT}] [{HIGH}]H:{h}[/{HIGH}] "
            f"[{MED}]M:{m}[/{MED}] [{LOW}]L:{lo}[/{LOW}]",
        )

    # ── Helpers ──
    def _refresh_modules(self) -> None:
        self._update_cell(
            "info_modules",
            f"[{TEXT_DIM}]MODULES[/{TEXT_DIM}]  {self.modules_done}/{self.modules_total}",
        )

    def _refresh_all(self) -> None:
        self.watch_target_name(self.target_name)
        self.watch_elapsed(self.elapsed)
        self._refresh_modules()
        self.watch_ai_active(self.ai_active)
        self.watch_finding_counts(self.finding_counts)

    def _update_cell(self, cell_id: str, text: str) -> None:
        try:
            self.query_one(f"#{cell_id}", Static).update(text)
        except Exception:
            pass
