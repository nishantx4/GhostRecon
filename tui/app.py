from textual.app import App, ComposeResult
from textual.widgets import Header, Footer
from tui.screens.target_setup import TargetSetupScreen
from tui.screens.dashboard import DashboardScreen
from tui.screens.report_view import ReportViewScreen

class GhostReconApp(App):
    """Main Textual application for GhostRecon v3.0."""
    
    CSS_PATH = "styles/ghostrecon.tcss"
    TITLE = "GhostRecon v3.0"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "export", "Export Report"),
        ("d", "toggle_dark", "Toggle Dark Mode"),
    ]

    def __init__(self, config=None, **kwargs):
        super().__init__(**kwargs)
        self.scan_config = config or {}
        self._ai_entry_map = {}  # track AI call entry IDs

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Footer()

    def on_mount(self) -> None:
        """Called when the app mounts."""
        self.install_screen(TargetSetupScreen(), name="setup")
        self.install_screen(DashboardScreen(), name="dashboard")
        self.install_screen(ReportViewScreen(), name="report")
        
        if self.scan_config.get("target"):
            self.push_screen("dashboard")
            # Initialize info bar with config data
            self._init_info_bar()
            self.run_worker(self._run_scan, thread=True)
        else:
            self.push_screen("setup")

    def start_scan_from_setup(self, config: dict) -> None:
        """Called by TargetSetupScreen once the user presses Start Scan."""
        self.scan_config = config
        self.push_screen("dashboard")
        self._init_info_bar()
        self.run_worker(self._run_scan, thread=True)

    def _init_info_bar(self):
        """Set initial values on the info bar from scan config."""
        try:
            dashboard = self.get_screen("dashboard")
            from tui.widgets.scan_info_bar import ScanInfoBar
            info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
            info_bar.target_name = self.scan_config.get("target", "—")
            info_bar.ai_active = bool(self.scan_config.get("api_key"))
            info_bar.start_timer()
        except Exception:
            pass
            
    def _run_scan(self) -> None:
        from core.session import ScanSession
        from core.ui import UI
        
        class TUIEmitter(UI):
            def __init__(self, callback):
                super().__init__(no_color=True)
                self.callback = callback
            def _print(self, *args, **kwargs):
                msg = " ".join(str(a) for a in args)
                if msg:
                    self.callback("log", {"text": msg})
                
        ui = TUIEmitter(self._handle_event)
        
        session = ScanSession(
            target=self.scan_config.get("target"),
            api_key=self.scan_config.get("api_key"),
            modules=self.scan_config.get("modules"),
            threads=self.scan_config.get("threads", 10),
            timeout=self.scan_config.get("timeout", 10),
            delay=self.scan_config.get("delay", 0.5),
            output_dir=self.scan_config.get("output_dir", "./ghostrecon_output"),
            ui=ui,
            event_callback=self._handle_event,
            auto_install_tools=self.scan_config.get("auto_install_tools", True),
            auth_headers=self.scan_config.get("auth_headers"),
            auth_cookies=self.scan_config.get("auth_cookies"),
        )
        try:
            session.run()
        except Exception as e:
            self.call_from_thread(self.notify, f"Scan failed: {e}", severity="error")
            
    def _handle_event(self, event_type: str, data: dict):
        """Called by ScanSession from the worker thread. Dispatch to main thread."""
        self.call_from_thread(self._process_event, event_type, data)
        
    def _process_event(self, event_type: str, data: dict):
        """Process event in the main thread (update UI)."""
        try:
            dashboard = self.get_screen("dashboard")
            if not dashboard.is_current:
                return

            from tui.widgets.scan_info_bar import ScanInfoBar
            from tui.widgets.ai_analysis_panel import AIAnalysisPanel
                
            if event_type == "scan_started":
                progress = dashboard.query_one("#progress_panel")
                progress.init_modules(data.get("modules", []))
                # Update info bar module count
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_total = len(data.get("modules", []))
                except Exception:
                    pass
                
            elif event_type == "module_started":
                progress = dashboard.query_one("#progress_panel")
                progress.start_module(data.get("module"))
                
            elif event_type == "module_completed":
                progress = dashboard.query_one("#progress_panel")
                progress.complete_module(data.get("module"))
                # Update info bar
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_done += 1
                except Exception:
                    pass

            elif event_type == "module_failed":
                progress = dashboard.query_one("#progress_panel")
                progress.fail_module(data.get("module"), data.get("error", ""))
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.modules_done += 1
                except Exception:
                    pass
                
            elif event_type == "finding_added":
                finding_panel = dashboard.query_one("#finding_panel")
                finding_panel.add_finding(
                    title=data.get("title", "Unknown"),
                    severity=data.get("severity", "info"),
                    url=data.get("url", ""),
                    confidence=data.get("confidence", ""),
                    module=data.get("module", ""),
                    description=data.get("description", ""),
                )
                
            elif event_type == "severity_updated":
                panel = dashboard.query_one("#finding_panel")
                panel.update_counts(
                    critical=data.get("critical", 0),
                    high=data.get("high", 0),
                    medium=data.get("medium", 0),
                    low=data.get("low", 0)
                )
                # Update info bar finding counts
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.finding_counts = data
                except Exception:
                    pass

            elif event_type == "ai_call_started":
                try:
                    ai_panel = dashboard.query_one("#ai_panel", AIAnalysisPanel)
                    method = data.get("method", "unknown")
                    context = data.get("context", "")
                    entry_id = ai_panel.add_ai_start(method, context)
                    # Store with a key so we can complete it later
                    call_key = f"{method}:{context}"
                    self._ai_entry_map[call_key] = entry_id
                except Exception:
                    pass

            elif event_type == "ai_call_completed":
                try:
                    ai_panel = dashboard.query_one("#ai_panel", AIAnalysisPanel)
                    method = data.get("method", "unknown")
                    context = data.get("context", "")
                    response = data.get("response", "")
                    call_key = f"{method}:{context}"
                    entry_id = self._ai_entry_map.pop(call_key, None)
                    if entry_id:
                        ai_panel.complete_ai_entry(entry_id, response)
                except Exception:
                    pass
                
            elif event_type == "log":
                # Dump logs into a rich log inside tool execution panel
                panel = dashboard.query_one("#tool_execution_panel")
                from textual.widgets import RichLog
                try:
                    log_widget = panel.query_one(RichLog)
                except:
                    log_widget = RichLog(highlight=True, markup=True, wrap=True)
                    panel.mount(log_widget)
                log_widget.write(data.get("text", ""))
                
            elif event_type == "scan_completed":
                self.notify("Scan completed!")
                # Stop the timer
                try:
                    info_bar = dashboard.query_one("#info_bar", ScanInfoBar)
                    info_bar.stop_timer()
                except Exception:
                    pass
                self.push_screen("report")
        except Exception as e:
            self.notify(f"UI Error: {e}", severity="error")
        
    def action_toggle_dark(self) -> None:
        """An action to toggle dark mode."""
        self.dark = not self.dark

if __name__ == "__main__":
    app = GhostReconApp()
    app.run()
