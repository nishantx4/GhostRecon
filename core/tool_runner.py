"""
External Tool Runner — Async subprocess executor for security tools.

Provides unified interface for running external tools (subfinder, nuclei, httpx, etc.)
with NDJSON stream parsing, timeout management, and event emission for the TUI.
"""

import asyncio
import json
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from core.tool_installer import BIN_DIR, ensure_path_includes_tools


@dataclass
class ToolResult:
    """Result from a single tool execution."""
    tool: str
    args: list[str]
    returncode: int = -1
    stdout_lines: list[str] = field(default_factory=list)
    stderr_lines: list[str] = field(default_factory=list)
    parsed_results: list[dict[str, Any]] = field(default_factory=list)
    elapsed: float = 0.0
    timed_out: bool = False
    skipped: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def result_count(self) -> int:
        return len(self.parsed_results) if self.parsed_results else len(self.stdout_lines)


@dataclass
class ToolStep:
    """A single step in a tool pipeline."""
    tool: str
    args: list[str]
    timeout: int = 300
    parse_json: bool = True
    description: str = ""
    # Optional: transform previous step's output into this step's stdin
    pipe_from_previous: bool = False


@dataclass
class PipelineResult:
    """Result from a sequential tool pipeline."""
    steps: list[ToolResult] = field(default_factory=list)
    total_elapsed: float = 0.0

    @property
    def all_success(self) -> bool:
        return all(s.success or s.skipped for s in self.steps)


class ExternalToolRunner:
    """
    Async executor for external security tools.

    Features:
    - NDJSON stream parsing for ProjectDiscovery tools
    - Timeout enforcement with graceful termination
    - Event callbacks for TUI integration
    - Sequential pipeline execution (tool A → tool B → tool C)
    - Graceful handling of missing tools (skip with warning)
    """

    def __init__(self, ui=None):
        self.ui = ui
        ensure_path_includes_tools()

    @staticmethod
    def is_installed(tool: str) -> bool:
        """Check if a tool binary is available."""
        ensure_path_includes_tools()
        return shutil.which(tool) is not None

    @staticmethod
    def get_available_tools() -> dict[str, bool]:
        """Return dict of {tool_name: is_installed} for all known tools."""
        ensure_path_includes_tools()
        tools = [
            "subfinder", "httpx", "nuclei", "katana", "dnsx",
            "ffuf", "dalfox", "interactsh-client", "gau", "waybackurls",
            "sqlmap", "wapiti", "feroxbuster", "gobuster", "wpscan",
        ]
        return {t: shutil.which(t) is not None for t in tools}

    async def run_tool(
        self,
        tool: str,
        args: list[str],
        timeout: int = 300,
        parse_json: bool = True,
        on_line: Callable[[str], None] | None = None,
        on_json: Callable[[dict], None] | None = None,
        stdin_data: str | None = None,
    ) -> ToolResult:
        """
        Execute an external tool and collect results.

        Args:
            tool: Binary name (e.g. 'subfinder')
            args: Command-line arguments
            timeout: Max execution time in seconds
            parse_json: If True, attempt to parse each stdout line as JSON
            on_line: Callback for each raw stdout line (for TUI streaming)
            on_json: Callback for each parsed JSON object
            stdin_data: Optional data to pipe to stdin
        """
        result = ToolResult(tool=tool, args=args)

        # Check tool availability
        tool_path = shutil.which(tool)
        if not tool_path:
            result.skipped = True
            result.error = f"Tool '{tool}' not installed"
            if self.ui:
                self.ui.warn(f"⊘ {tool} not installed — skipping")
            return result

        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                tool_path, *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
            )

            # Send stdin if provided
            if stdin_data and proc.stdin:
                proc.stdin.write(stdin_data.encode("utf-8"))
                await proc.stdin.drain()
                proc.stdin.close()

            async def read_stdout():
                while proc.stdout:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if not decoded:
                        continue

                    result.stdout_lines.append(decoded)
                    if on_line:
                        on_line(decoded)

                    if parse_json:
                        try:
                            data = json.loads(decoded)
                            result.parsed_results.append(data)
                            if on_json:
                                on_json(data)
                        except json.JSONDecodeError:
                            pass  # Non-JSON lines are normal

            async def read_stderr():
                while proc.stderr:
                    line = await proc.stderr.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="replace").rstrip()
                    if decoded:
                        result.stderr_lines.append(decoded)

            try:
                await asyncio.wait_for(
                    asyncio.gather(read_stdout(), read_stderr(), proc.wait()),
                    timeout=timeout,
                )
                result.returncode = proc.returncode or 0
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                result.timed_out = True
                result.error = f"Tool timed out after {timeout}s"
                if self.ui:
                    self.ui.warn(f"⏱ {tool} timed out after {timeout}s")

        except FileNotFoundError:
            result.skipped = True
            result.error = f"Binary not found: {tool}"
        except PermissionError:
            result.error = f"Permission denied: {tool}"
        except Exception as e:
            result.error = f"Execution error: {e}"

        result.elapsed = time.monotonic() - start
        return result

    async def run_pipeline(
        self,
        steps: list[ToolStep],
        on_step_start: Callable[[int, ToolStep], None] | None = None,
        on_step_complete: Callable[[int, ToolResult], None] | None = None,
    ) -> PipelineResult:
        """
        Run a sequential pipeline of tools.
        Each tool runs to completion before the next starts.
        Output from one step can be piped to the next.
        """
        pipeline = PipelineResult()
        start = time.monotonic()
        previous_output: str | None = None

        for i, step in enumerate(steps):
            if on_step_start:
                on_step_start(i, step)

            if self.ui:
                desc = step.description or f"{step.tool} {' '.join(step.args[:3])}"
                self.ui.info(f"▸ Running: {desc}")

            stdin_data = None
            if step.pipe_from_previous and previous_output:
                stdin_data = previous_output

            result = await self.run_tool(
                tool=step.tool,
                args=step.args,
                timeout=step.timeout,
                parse_json=step.parse_json,
            )

            pipeline.steps.append(result)

            if on_step_complete:
                on_step_complete(i, result)

            # Prepare output for piping to next step
            if result.stdout_lines:
                previous_output = "\n".join(result.stdout_lines)
            else:
                previous_output = None

            if self.ui:
                if result.success:
                    self.ui.ok(f"  ✓ {step.tool} completed ({result.elapsed:.1f}s, {result.result_count} results)")
                elif result.skipped:
                    self.ui.warn(f"  ⊘ {step.tool} skipped (not installed)")
                else:
                    self.ui.warn(f"  ✗ {step.tool} failed: {result.error}")

        pipeline.total_elapsed = time.monotonic() - start
        return pipeline

    def run_sync(
        self,
        tool: str,
        args: list[str],
        timeout: int = 300,
        parse_json: bool = True,
        on_line: Callable[[str], None] | None = None,
    ) -> ToolResult:
        """
        Synchronous wrapper for run_tool().
        Use this from module run() methods that can't be async.
        """
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # We're inside an async context — create a new thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(
                        asyncio.run,
                        self.run_tool(tool, args, timeout, parse_json, on_line),
                    )
                    return future.result(timeout=timeout + 10)
            else:
                return loop.run_until_complete(
                    self.run_tool(tool, args, timeout, parse_json, on_line)
                )
        except RuntimeError:
            return asyncio.run(
                self.run_tool(tool, args, timeout, parse_json, on_line)
            )

    def run_pipeline_sync(self, steps: list[ToolStep]) -> PipelineResult:
        """Synchronous wrapper for run_pipeline()."""
        try:
            return asyncio.run(self.run_pipeline(steps))
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(self.run_pipeline(steps))
            finally:
                loop.close()
