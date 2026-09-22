"""
Tool Installer — Auto-installs missing external security tools.

Downloads pre-built binaries from GitHub Releases to ~/.ghostrecon/tools/bin/.
No Docker, no system-wide pollution, no Go compiler required.
"""

import os
import sys
import json
import shutil
import zipfile
import tarfile
import platform
import tempfile
import requests as _requests
from pathlib import Path
from typing import Callable

# ── Tool install directory ─────────────────────────────────────────────────────
TOOLS_DIR = Path.home() / ".ghostrecon" / "tools"
BIN_DIR   = TOOLS_DIR / "bin"

# ── OS / Arch detection ───────────────────────────────────────────────────────
def _detect_platform() -> tuple[str, str]:
    """Detect OS and architecture for binary downloads."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    os_map = {"windows": "windows", "linux": "linux", "darwin": "darwin"}
    os_name = os_map.get(system, system)

    arch_map = {
        "x86_64": "amd64", "amd64": "amd64",
        "aarch64": "arm64", "arm64": "arm64",
        "x86": "386", "i686": "386", "i386": "386",
    }
    arch = arch_map.get(machine, machine)

    return os_name, arch


# ── Tool Registry ─────────────────────────────────────────────────────────────
# Each entry: { binary_name, github_repo, asset_pattern, install_type }
# asset_pattern uses {os} and {arch} placeholders

TOOL_REGISTRY: dict[str, dict] = {
    "subfinder": {
        "binary": "subfinder",
        "repo": "projectdiscovery/subfinder",
        "asset_pattern": "subfinder_{version}_{os}_{arch}",
        "description": "Fast passive subdomain enumeration",
    },
    "httpx": {
        "binary": "httpx",
        "repo": "projectdiscovery/httpx",
        "asset_pattern": "httpx_{version}_{os}_{arch}",
        "description": "Fast HTTP toolkit for probing live hosts",
    },
    "nuclei": {
        "binary": "nuclei",
        "repo": "projectdiscovery/nuclei",
        "asset_pattern": "nuclei_{version}_{os}_{arch}",
        "description": "Vulnerability scanner with 8000+ templates",
    },
    "katana": {
        "binary": "katana",
        "repo": "projectdiscovery/katana",
        "asset_pattern": "katana_{version}_{os}_{arch}",
        "description": "Next-gen web crawler with JS parsing",
    },
    "dnsx": {
        "binary": "dnsx",
        "repo": "projectdiscovery/dnsx",
        "asset_pattern": "dnsx_{version}_{os}_{arch}",
        "description": "Multi-purpose DNS toolkit",
    },
    "ffuf": {
        "binary": "ffuf",
        "repo": "ffuf/ffuf",
        "asset_pattern": "ffuf_{version}_{os}_{arch}",
        "description": "Fast web fuzzer for content discovery",
    },
    "dalfox": {
        "binary": "dalfox",
        "repo": "hahwul/dalfox",
        "asset_pattern": "dalfox_{version}_{os}_{arch}",
        "description": "XSS scanner and parameter analyzer",
    },
    "interactsh-client": {
        "binary": "interactsh-client",
        "repo": "projectdiscovery/interactsh",
        "asset_pattern": "interactsh-client_{version}_{os}_{arch}",
        "description": "Out-of-band interaction server client",
    },
    "gau": {
        "binary": "gau",
        "repo": "lc/gau",
        "asset_pattern": "gau_{version}_{os}_{arch}",
        "description": "Fetch known URLs from multiple sources",
    },
    "waybackurls": {
        "binary": "waybackurls",
        "repo": "tomnomnom/waybackurls",
        "asset_pattern": "waybackurls-{os}-{arch}-{version}",
        "description": "Fetch URLs from Wayback Machine",
    },
}

# Python-based tools installed via pip
PIP_TOOLS: dict[str, dict] = {
    "sqlmap": {
        "package": "sqlmap",
        "binary": "sqlmap",
        "description": "SQL injection detection and exploitation",
    },
    "wapiti": {
        "package": "wapiti3",
        "binary": "wapiti",
        "description": "Web application vulnerability scanner",
    },
}


class ToolInstaller:
    """Auto-installs missing external security tools."""

    def __init__(self, ui=None, on_progress: Callable | None = None):
        self.ui = ui
        self.on_progress = on_progress
        self.os_name, self.arch = _detect_platform()
        BIN_DIR.mkdir(parents=True, exist_ok=True)

    def get_tool_path(self, tool_name: str) -> str | None:
        """Get the full path to a tool binary. Returns None if not found."""
        # Check our managed tools directory first
        ext = ".exe" if self.os_name == "windows" else ""
        local_bin = BIN_DIR / f"{tool_name}{ext}"
        if local_bin.exists():
            return str(local_bin)

        # Check system PATH
        system_path = shutil.which(tool_name)
        if system_path:
            return system_path

        return None

    def is_installed(self, tool_name: str) -> bool:
        """Check if a tool is available (locally or on PATH)."""
        return self.get_tool_path(tool_name) is not None

    def get_all_status(self) -> dict[str, dict]:
        """Get installation status of all known tools."""
        status = {}
        for name, info in {**TOOL_REGISTRY, **PIP_TOOLS}.items():
            binary = info.get("binary", name)
            path = self.get_tool_path(binary)
            status[name] = {
                "installed": path is not None,
                "path": path,
                "description": info.get("description", ""),
            }
        return status

    def ensure_tools(self, tool_names: list[str]) -> dict[str, bool]:
        """
        Ensure all specified tools are installed. Auto-installs missing ones.
        Returns dict of {tool_name: success}.
        """
        results = {}
        missing = [t for t in tool_names if not self.is_installed(t)]

        if not missing:
            return {t: True for t in tool_names}

        if self.ui:
            self.ui.info(f"Installing {len(missing)} missing tool(s): {', '.join(missing)}")

        for tool in missing:
            try:
                success = self._install_tool(tool)
                results[tool] = success
                if self.ui:
                    if success:
                        self.ui.ok(f"✓ Installed {tool}")
                    else:
                        self.ui.warn(f"✗ Failed to install {tool} — will use built-in fallback")
            except Exception as e:
                results[tool] = False
                if self.ui:
                    self.ui.warn(f"✗ Error installing {tool}: {e}")

        # Mark already-installed tools
        for tool in tool_names:
            if tool not in results:
                results[tool] = True

        return results

    def _install_tool(self, tool_name: str) -> bool:
        """Install a single tool. Returns True on success."""
        if tool_name in TOOL_REGISTRY:
            return self._install_github_release(tool_name, TOOL_REGISTRY[tool_name])
        elif tool_name in PIP_TOOLS:
            return self._install_pip_tool(tool_name, PIP_TOOLS[tool_name])
        else:
            if self.ui:
                self.ui.warn(f"Unknown tool: {tool_name}")
            return False

    def _install_github_release(self, tool_name: str, info: dict) -> bool:
        """Download and install a tool from its GitHub release."""
        repo = info["repo"]
        binary = info.get("binary", tool_name)

        if self.ui:
            self.ui.info(f"Fetching latest release for {tool_name}...")

        # Get latest release info from GitHub API
        api_url = f"https://api.github.com/repos/{repo}/releases/latest"
        try:
            resp = _requests.get(api_url, timeout=30, headers={"Accept": "application/vnd.github.v3+json"})
            resp.raise_for_status()
            release = resp.json()
        except Exception as e:
            if self.ui:
                self.ui.error(f"Failed to fetch release info for {repo}: {e}")
            return False

        version = release.get("tag_name", "").lstrip("v")
        assets = release.get("assets", [])

        # Find matching asset for our platform
        target_asset = self._find_matching_asset(assets, tool_name, version)
        if not target_asset:
            if self.ui:
                self.ui.error(f"No binary found for {tool_name} on {self.os_name}/{self.arch}")
            return False

        # Download
        download_url = target_asset["browser_download_url"]
        asset_name = target_asset["name"]
        if self.ui:
            self.ui.info(f"Downloading {asset_name}...")

        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_path = os.path.join(tmp_dir, asset_name)
                self._download_file(download_url, tmp_path)

                # Extract binary
                ext = ".exe" if self.os_name == "windows" else ""
                target_bin = BIN_DIR / f"{binary}{ext}"

                if asset_name.endswith(".zip"):
                    self._extract_zip(tmp_path, tmp_dir, binary, ext)
                elif asset_name.endswith((".tar.gz", ".tgz")):
                    self._extract_tar(tmp_path, tmp_dir, binary, ext)
                else:
                    # Assume it's a raw binary
                    shutil.copy2(tmp_path, target_bin)

                # Find the extracted binary
                extracted = self._find_binary_in_dir(tmp_dir, binary, ext)
                if extracted:
                    shutil.copy2(extracted, target_bin)
                    if self.os_name != "windows":
                        os.chmod(target_bin, 0o755)
                    return True
                elif target_bin.exists():
                    if self.os_name != "windows":
                        os.chmod(target_bin, 0o755)
                    return True
                else:
                    if self.ui:
                        self.ui.error(f"Could not find {binary} binary in downloaded archive")
                    return False

        except Exception as e:
            if self.ui:
                self.ui.error(f"Download/extract failed for {tool_name}: {e}")
            return False

    def _find_matching_asset(self, assets: list, tool_name: str, version: str) -> dict | None:
        """Find the correct release asset for our OS/arch."""
        os_variants = {
            "windows": ["windows", "win"],
            "linux": ["linux"],
            "darwin": ["darwin", "macos", "osx", "macOS"],
        }
        arch_variants = {
            "amd64": ["amd64", "x86_64", "x64"],
            "arm64": ["arm64", "aarch64"],
            "386": ["386", "i386", "x86", "i686"],
        }

        os_names = os_variants.get(self.os_name, [self.os_name])
        arch_names = arch_variants.get(self.arch, [self.arch])

        # Score each asset by how well it matches
        best_match = None
        best_score = -1

        for asset in assets:
            name = asset["name"].lower()

            # Skip checksums, signatures, source archives
            if any(name.endswith(ext) for ext in [".txt", ".sig", ".asc", ".sha256", ".md5"]):
                continue

            # Must match OS
            os_match = any(os_v in name for os_v in os_names)
            if not os_match:
                continue

            # Must match architecture
            arch_match = any(arch_v in name for arch_v in arch_names)
            if not arch_match:
                continue

            # Prefer zip on Windows, tar.gz on Linux/Mac
            score = 1
            if self.os_name == "windows" and name.endswith(".zip"):
                score += 2
            elif self.os_name != "windows" and name.endswith((".tar.gz", ".tgz")):
                score += 2

            if score > best_score:
                best_score = score
                best_match = asset

        return best_match

    def _download_file(self, url: str, dest_path: str):
        """Download a file with progress tracking."""
        resp = _requests.get(url, stream=True, timeout=120)
        resp.raise_for_status()
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0

        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
                if self.on_progress and total > 0:
                    self.on_progress(downloaded, total)

    def _extract_zip(self, zip_path: str, dest_dir: str, binary: str, ext: str):
        """Extract a zip archive."""
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(dest_dir)

    def _extract_tar(self, tar_path: str, dest_dir: str, binary: str, ext: str):
        """Extract a tar.gz archive."""
        with tarfile.open(tar_path, "r:gz") as tf:
            tf.extractall(dest_dir, filter="data")

    def _find_binary_in_dir(self, dir_path: str, binary: str, ext: str) -> str | None:
        """Recursively search for the target binary in extracted files."""
        target = f"{binary}{ext}"
        for root, dirs, files in os.walk(dir_path):
            for f in files:
                if f.lower() == target.lower():
                    return os.path.join(root, f)
                # Some tools have versioned names
                if f.lower().startswith(binary.lower()) and f.lower().endswith(ext if ext else ""):
                    full = os.path.join(root, f)
                    if os.access(full, os.X_OK) or ext == ".exe":
                        return full
        return None

    def _install_pip_tool(self, tool_name: str, info: dict) -> bool:
        """Install a Python-based tool via pip."""
        package = info["package"]
        if self.ui:
            self.ui.info(f"Installing {package} via pip...")
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", package],
                capture_output=True, text=True, timeout=120,
            )
            return result.returncode == 0
        except Exception as e:
            if self.ui:
                self.ui.error(f"pip install failed for {package}: {e}")
            return False


def ensure_path_includes_tools():
    """Add ~/.ghostrecon/tools/bin to PATH if not already present."""
    bin_str = str(BIN_DIR)
    if bin_str not in os.environ.get("PATH", ""):
        os.environ["PATH"] = bin_str + os.pathsep + os.environ.get("PATH", "")
