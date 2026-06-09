<div align="center">

```
   _____ _               _   _____
  / ____| |             | | |  __ \
 | |  __| |__   ___  ___| |_| |__) |___  ___ ___  _ __
 | | |_ | '_ \ / _ \/ __| __|  _  // _ \/ __/ _ \| '_ \
 | |__| | | | | (_) \__ \ |_| | \ \  __/ (_| (_) | | | |
  \_____|_| |_|\___/|___/\__|_|  \_\___|\___|___/|_| |_|
```

# GhostRecon 👻

**AI-Powered Bug Bounty Hunter CLI**

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Claude AI](https://img.shields.io/badge/Claude-AI%20Powered-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Made by](https://img.shields.io/badge/Made%20by-Nishant-a855f7?style=for-the-badge)](https://github.com/yourusername)

*A personal bug bounty hunting companion — built to make recon smarter, faster, and more fun.*

</div>

---

## 🤔 What is GhostRecon?

GhostRecon is a modular, AI-assisted recon and vulnerability scanning CLI tool designed for bug bounty hunters. Point it at a target domain and it crawls endpoints, detects common vulnerabilities (XSS, SQLi, IDOR, SSRF, CORS misconfigs, and more), then optionally sends findings to **Claude AI** for vulnerability chain analysis and estimated bounty values.

Think of it as your personal ghost that haunts a target and reports back everything it finds. 👻

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Smart Recon** | Crawls endpoints, extracts forms, probes common paths |
| 🛡️ **14 Scan Modules** | XSS, SQLi, IDOR, SSRF, CORS, GraphQL, HTTP Smuggling, Secrets & more |
| 🤖 **Claude AI Integration** | Analyzes vulnerability chains, estimates bounty values, generates PoC outlines |
| 📊 **Rich Terminal UI** | Color-coded severity output, spinners, progress bars, tables |
| 📄 **Auto Reports** | Generates Markdown bug bounty reports + JSON data + shell command runbooks |
| 🎮 **Interactive Mode** | Menu-driven interface — no flags needed |
| ⚡ **Multi-threaded** | Configurable thread pool for faster scanning |
| 🔌 **Local Fallback** | Full rule-based chain analysis even without an API key |

---

## 📦 Installation

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/ghostrecon.git
cd ghostrecon

# 2. Install dependencies
pip install requests anthropic

# 3. Run it!
python ghostrecon.py --help
```

> **Note:** `anthropic` is only needed if you want Claude AI analysis. The tool runs fully offline without it.

---

## 🚀 Usage

### Quick Start
```bash
# Basic scan (default modules)
python ghostrecon.py -t example.com

# Full scan — all 14 modules
python ghostrecon.py -t example.com --full

# With Claude AI analysis
python ghostrecon.py -t example.com --api-key sk-ant-...

# Interactive mode (guided menu)
python ghostrecon.py --interactive
```

### Pick Your Modules
```bash
# Only run specific modules
python ghostrecon.py -t example.com --modules recon,xss,sqli,idor
```

### All Options
```
  -t, --target        Target domain (e.g. example.com)
  --api-key           Anthropic Claude API key (enables AI analysis)
  --full              Run all 14 modules
  --modules           Comma-separated list of modules to run
  --scope             Define in-scope assets
  --output            Custom output report filename
  --output-dir        Output directory (default: ./ghostrecon_output)
  --threads           Number of threads (default: 10)
  --timeout           Request timeout in seconds (default: 10)
  --delay             Delay between requests (default: 0.5s)
  --verbose, -v       Verbose output
  --interactive, -i   Interactive menu mode
  --no-color          Disable colored output
  --version           Show version
```

---

## 🧩 Modules

| Module | Flag | What it does |
|---|---|---|
| `recon` | default | Crawls the target, discovers endpoints & forms |
| `headers` | default | Checks for missing security headers |
| `js` | default | Analyzes JavaScript files for secrets & API keys |
| `params` | default | Identifies injectable URL parameters |
| `nuclei` | default | Simulates common CVE/template checks |
| `xss` | default | Tests for reflected & stored XSS |
| `idor` | default | Detects Insecure Direct Object References |
| `cors` | default | Checks CORS misconfiguration |
| `ssrf` | default | Probes for Server-Side Request Forgery |
| `sqli` | `--full` | Tests for SQL Injection (multiple techniques) |
| `graphql` | `--full` | GraphQL introspection & mutation abuse |
| `smuggling` | `--full` | HTTP Request Smuggling detection |
| `secrets` | `--full` | Hunts for exposed secrets, `.env` files, backups |
| `report` | always | Generates the final Markdown + JSON report |

---

## 🤖 AI-Powered Chain Analysis

When you provide an Anthropic API key, GhostRecon sends all findings to **Claude** after the scan completes. Claude will:

- 🔗 Identify **vulnerability chains** (e.g. SSRF → Credential Exposure → Cloud Takeover)
- 💰 Estimate **bounty ranges** per finding
- 🗺️ Map out the **single highest-impact attack path**
- 📋 Generate **PoC outlines** for the top 3 findings

No API key? No problem — the built-in local engine still identifies common chains and priorities.

---

## 📁 Output

Every scan generates three files in `./ghostrecon_output/`:

```
ghostrecon_output/
├── ghostrecon_example.com_20260609_120000.json      ← Raw findings data
├── ghostrecon_example.com_20260609_120000.md         ← Full Markdown report
└── ghostrecon_example.com_20260609_120000_commands.sh ← Shell command runbook
```

The Markdown report is ready to submit directly to **HackerOne**, **Bugcrowd**, or any bug bounty platform.

---

## ⚠️ Legal Disclaimer

> **GhostRecon is intended for authorized security testing only.**
>
> Only use this tool against targets you own or have explicit written permission to test.
> Unauthorized use against third-party systems is illegal and unethical.
> The author takes no responsibility for misuse.

---

## 🛠️ Project Structure

```
ghostrecon/
├── ghostrecon.py          ← Entry point & CLI argument parser
├── core/
│   ├── banner.py          ← ASCII art banner & startup display
│   ├── session.py         ← Scan orchestrator (runs all modules)
│   ├── ai_engine.py       ← Claude API + local fallback engine
│   ├── interactive.py     ← Interactive menu mode
│   ├── findings.py        ← Findings database
│   └── ui.py              ← Terminal colors, spinners, tables
└── modules/
    ├── recon.py           ← Crawler & endpoint discovery
    ├── headers.py         ← Security headers checker
    ├── js_analysis.py     ← JavaScript secrets scanner
    ├── xss.py             ← XSS detection engine
    ├── sqli.py            ← SQL Injection tester
    ├── idor.py            ← IDOR detector
    ├── cors.py            ← CORS misconfiguration checker
    ├── ssrf.py            ← SSRF prober
    ├── secrets.py         ← Secrets & sensitive file hunter
    ├── nuclei_sim.py      ← Nuclei-style template checks
    ├── graphql.py         ← GraphQL tester
    ├── smuggling.py       ← HTTP Smuggling detector
    ├── params.py          ← Parameter discovery
    └── reporter.py        ← Report generator
```

---

## 🤝 Contributing

Got a module idea or a better payload list? PRs are welcome!

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes
4. Open a Pull Request

---

<div align="center">

Made with 👻 by **Nishant**

*Happy hunting — and always hack ethically!*

</div>
