from textual.screen import Screen
from textual.widgets import Label, Button, Input, Checkbox, Static
from textual.containers import Vertical, Horizontal, ScrollableContainer
from textual.app import ComposeResult

class TargetSetupScreen(Screen):
    """Initial screen to setup target and scan options."""
    
    def compose(self) -> ComposeResult:
        yield ScrollableContainer(
            Static("GhostRecon Target Setup", classes="title"),
            Vertical(
                Label("Target Domain:"),
                Input(placeholder="example.com", id="target_input"),
                Label("Thread Count:"),
                Input(value="10", id="thread_input"),
                classes="input-group"
            ),
            Horizontal(
                Button("Quick Profile", id="profile_quick"),
                Button("Standard Profile", id="profile_standard"),
                Button("Full Profile", id="profile_full"),
                classes="profile-buttons"
            ),
            Vertical(
                Label("Module Selection:"),
                Checkbox("Reconnaissance", id="mod_recon", value=True),
                Checkbox("Passive Analysis", id="mod_passive", value=True),
                Checkbox("Injection", id="mod_injection", value=True),
                classes="module-group"
            ),
            Horizontal(
                Label("API Key Status:"),
                Label("CONFIGURED", classes="status-success", id="api_status"),
                classes="status-group"
            ),
            Button("Start Scan", id="start_btn", variant="success")
        )
        
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "start_btn":
            self.app.push_screen("dashboard")
