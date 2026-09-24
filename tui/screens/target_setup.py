from textual.screen import Screen
from textual.widgets import Label, Button, Input, Checkbox, Static
from textual.containers import Vertical, Horizontal, Grid, ScrollableContainer
from textual.app import ComposeResult

from core.banner import BANNER, TAGLINE
from core.session import MODULE_LABELS, PRESETS
import core.config as config


class TargetSetupScreen(Screen):
    """Initial screen to setup target and scan options."""

    def compose(self) -> ComposeResult:
        api_key = config.get_api_key()
        status_text  = "CONFIGURED" if api_key else "NOT SET"
        status_class = "status-success" if api_key else "status-fail"

        standard_set = set(PRESETS["standard"])
        module_checkboxes = [
            Checkbox(
                label, id=f"mod_{mod_id}", value=mod_id in standard_set,
                classes="module-checkbox",
            )
            for mod_id, label in MODULE_LABELS.items() if mod_id != "report"
        ]

        yield ScrollableContainer(
            Static(BANNER, classes="banner", markup=True),
            Static(f"AI BUG BOUNTY HUNTER · v3.0  —  {TAGLINE.strip()}", classes="subtitle"),
            Vertical(
                Label("Target Domain:", classes="section-label"),
                Input(placeholder="example.com", id="target_input"),
                Label("Thread Count:", classes="section-label"),
                Input(value="10", id="thread_input"),
                Label("Auth Header (optional — scan authenticated areas):", classes="section-label"),
                Input(placeholder='X-Auth-Token: abc123  (or  Cookie: session=abc123)', id="auth_header_input"),
                classes="input-group"
            ),
            Horizontal(
                Button("Quick Profile", id="profile_quick"),
                Button("Standard Profile", id="profile_standard"),
                Button("Full Profile", id="profile_full"),
                classes="profile-buttons"
            ),
            Vertical(
                Label("Module Selection:", classes="section-label"),
                Grid(*module_checkboxes, id="module_grid"),
                classes="module-group"
            ),
            Horizontal(
                Label("API Key Status:", classes="status-label"),
                Label(status_text, classes=status_class, id="api_status"),
                classes="status-group"
            ),
            Button("Start Scan", id="start_btn", variant="success")
        )

    def _set_modules(self, preset: str) -> None:
        selected = set(PRESETS.get(preset, PRESETS["standard"]))
        for cb in self.query(".module-checkbox"):
            mod_id = cb.id[len("mod_"):]
            cb.value = mod_id in selected

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "profile_quick":
            self._set_modules("quick")
        elif event.button.id == "profile_standard":
            self._set_modules("standard")
        elif event.button.id == "profile_full":
            self._set_modules("full")
        elif event.button.id == "start_btn":
            self._start_scan()

    def _start_scan(self) -> None:
        target = self.query_one("#target_input", Input).value.strip()
        if not target:
            self.app.notify("Enter a target domain first.", severity="error")
            return

        try:
            threads = int(self.query_one("#thread_input", Input).value.strip() or "10")
        except ValueError:
            threads = 10

        selected_modules = [
            cb.id[len("mod_"):] for cb in self.query(".module-checkbox") if cb.value
        ]
        if not selected_modules:
            self.app.notify("Select at least one module.", severity="error")
            return
        selected_modules.append("report")

        auth_headers, auth_cookies = {}, {}
        auth_line = self.query_one("#auth_header_input", Input).value.strip()
        if auth_line:
            name, sep, value = auth_line.partition(":")
            if sep:
                name, value = name.strip(), value.strip()
                if name.lower() == "cookie":
                    for pair in value.split(";"):
                        cname, csep, cval = pair.strip().partition("=")
                        if csep:
                            auth_cookies[cname.strip()] = cval.strip()
                else:
                    auth_headers[name] = value
            else:
                self.app.notify('Auth header ignored — expected "Name: Value" format.', severity="warning")

        self.app.start_scan_from_setup({
            "target": target,
            "api_key": config.get_api_key(),
            "modules": selected_modules,
            "threads": threads,
            "timeout": 10,
            "delay": 0.5,
            "output_dir": "./ghostrecon_output",
            "auth_headers": auth_headers,
            "auth_cookies": auth_cookies,
        })
