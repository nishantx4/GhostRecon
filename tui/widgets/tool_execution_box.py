import asyncio
import time
from textual.widgets import Collapsible, RichLog
from textual import work
from textual.reactive import reactive

class ToolExecutionBox(Collapsible):
    """Collapsible widget showing live streaming stdout/stderr."""
    
    status = reactive("PENDING")
    elapsed_time = reactive(0.0)

    def __init__(self, command: str, **kwargs):
        super().__init__(title=f"[PENDING] {command} (0.0s)", **kwargs)
        self.command = command
        self.log_widget = RichLog(highlight=True, markup=True)
        self.start_time = None

    def compose(self):
        yield self.log_widget

    def watch_status(self, old_status: str, new_status: str) -> None:
        self._update_title()
        
    def watch_elapsed_time(self, old_time: float, new_time: float) -> None:
        self._update_title()

    def _update_title(self) -> None:
        icons = {
            "PENDING": "⏳ PENDING",
            "RUNNING": "⚡ RUNNING",
            "SUCCESS": "✓ SUCCESS",
            "FAILED": "❌ FAILED"
        }
        icon = icons.get(self.status, self.status)
        self.title = f"[{icon}] {self.command} ({self.elapsed_time:.1f}s)"

    @work(thread=True)
    async def execute(self):
        self.status = "RUNNING"
        self.start_time = time.time()
        
        proc = await asyncio.create_subprocess_shell(
            self.command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        async def update_timer():
            while self.status == "RUNNING":
                self.elapsed_time = time.time() - self.start_time
                await asyncio.sleep(0.2)
                
        timer_task = asyncio.create_task(update_timer())
        
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            self.log_widget.write(line.decode().strip())
            
        await proc.wait()
        self.status = "SUCCESS" if proc.returncode == 0 else "FAILED"
        self.elapsed_time = time.time() - self.start_time
        await timer_task
