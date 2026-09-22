# GhostRecon v3.0
**AI-Powered Bug Bounty Hunter & Vulnerability Scanner**

GhostRecon v3.0 is a next-generation bug bounty and reconnaissance framework that marries traditional security tooling with an advanced AI verification engine. Built to eliminate false positives and stream execution output live via a gorgeous Textual Terminal UI (TUI), GhostRecon v3.0 represents a massive overhaul from previous versions.

## Features

- **Gorgeous Textual TUI:** A fully asynchronous, interactive 3-panel dashboard that tracks scan progress, live streams external tool outputs, and aggregates verified vulnerabilities in real-time.
- **35 Vulnerability Modules:** GhostRecon detects 35 different classes of vulnerabilities including SQLi, NoSQLi, XSS, XXE, Command Injection, Prototype Pollution, IDOR, Mass Assignment, GraphQL Batching DoS, HTTP Request Smuggling, and more.
- **Phase 0 Baseline Fingerprinting:** GhostRecon automatically calculates standard deviation/variance for network jitter, identifies Single Page Applications (SPA), fingerprints WAFs, and structurally diffs custom Soft-404 error pages to drastically eliminate false positives on blind attacks.
- **AI Validator Engine:** Deep integration with NVIDIA NIM APIs (e.g., `llama-3.1-70b-instruct`) allows GhostRecon to read DOM structures and validate high-entropy findings.
- **External Tool Pipeline:** Automatically pipes targets through `subfinder`, `waybackurls`, `katana`, and `nuclei` if installed, seamlessly falling back to native Python engines if not available.
- **Bundled Wordlists:** Comes packaged with `data/common.txt` containing 100 high-value endpoints for directory fuzzing.

---

## Installation

Ensure you have Python 3.10+ installed.

```bash
# Clone the repository
git clone https://github.com/nishant/ghostrecon.git
cd ghostrecon

# Install dependencies using poetry or pip
pip install -r requirements.txt
# OR
poetry install
```

---

## Usage & Commands

GhostRecon is invoked via `ghostrecon.py`. By default, if a target is provided, it launches the interactive Textual Dashboard.

### Basic Scan
```bash
python ghostrecon.py -t example.com
```

### AI Configuration (Highly Recommended)
GhostRecon relies on the NVIDIA NIM API for the Validator engine. Get a free API key at `build.nvidia.com`.
```bash
python ghostrecon.py --set-api nvapi-xxxx
python ghostrecon.py --api-test
```

### Scan Presets
You can specify the depth of the scan using presets:
```bash
# Quick profile (Recon, CMS, Headers, Secrets, CORS, Nuclei)
python ghostrecon.py -t example.com --preset quick

# Standard profile (Default - strikes a balance between speed and coverage)
python ghostrecon.py -t example.com --preset standard

# Full profile (Runs all 35 modules, extremely thorough and loud)
python ghostrecon.py -t example.com --preset full
```

### Custom Modules
If you want to only run specific modules (e.g. only XSS and GraphQL):
```bash
python ghostrecon.py -t example.com --modules xss,graphql
```

### Legacy Headless & Output Flags
```bash
# Disable the TUI and run as standard stdout CLI (Useful for CI/CD)
python ghostrecon.py -t example.com --no-tui

# Save report output to a specific directory
python ghostrecon.py -t example.com --output-dir ./my_reports/
```

---

## Flags & Arguments

### NVIDIA AI Key Management
| Flag | Description |
|------|-------------|
| `--set-api KEY` | Save your NVIDIA NIM API key persistently |
| `--remove-api` | Remove the saved NVIDIA API key |
| `--api-test` | Test whether the saved (or provided) API key is working |

### Scan Options
| Flag | Description |
|------|-------------|
| `-t`, `--target` | Target domain (e.g. example.com) |
| `--api-key` | Temporary NVIDIA API key (overrides saved config) |
| `--preset` | Scan profile preset: `quick`, `standard`, `full` |
| `--modules` | Comma-separated modules to run (overrides preset) |
| `--output-dir` | Output directory (default: `./ghostrecon_output`) |
| `--threads` | Thread count (default: 10) |
| `--timeout` | Request timeout in seconds (default: 10s) |
| `--delay` | Delay between requests in seconds (default: 0.5s) |
| `--no-tui` | Disable Textual TUI and run in legacy headless mode |
| `--no-color` | Disable colored output in headless mode |
| `--interactive`, `-i` | Launch the legacy interactive setup menu |

---

## License

Please see `LICENSE` for usage restrictions.
