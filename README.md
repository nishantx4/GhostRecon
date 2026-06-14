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
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM%20AI-76B900?style=for-the-badge&logo=nvidia&logoColor=white)](https://build.nvidia.com/)
[![License](https://img.shields.io/badge/License-GPL%20v3-22c55e?style=for-the-badge)](LICENSE)
[![Made by](https://img.shields.io/badge/Made%20by-Nishant-a855f7?style=for-the-badge)](https://github.com/nishantx4)

*Your personal bug bounty hunting companion — built to make recon smarter, faster, and more fun.*

</div>

---

## 🤔 What is GhostRecon?

GhostRecon is a modular, AI-assisted recon and vulnerability scanning CLI tool built for bug bounty hunters. Point it at a target domain and it crawls endpoints, detects common vulnerabilities (XSS, SQLi, IDOR, SSRF, CORS misconfigs, and more), then uses **NVIDIA NIM AI (free tier)** not just to generate reports — but to actively *help during the hunt itself*.

The AI ranks your endpoints, deep-dives JavaScript files, validates IDOR findings, assesses header risks, and generates targeted payloads — all while you scan.

Think of it as your personal ghost that haunts a target and reports back everything it finds. 👻

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Smart Recon** | Crawls endpoints, extracts forms, probes common paths |
| 🛡️ **14 Scan Modules** | XSS, SQLi, IDOR, SSRF, CORS, GraphQL, HTTP Smuggling, Secrets & more |
| 🤖 **NVIDIA NIM AI** | Free-tier AI that actively helps during scanning — not just reports |
| 🎯 **Active AI Hunting** | Endpoint prioritization, JS deep-analysis, IDOR validation, payload generation |
| 🔑 **Persistent API Key** | Set once with `--set-api`, automatically used on every scan |
| 📊 **Rich Terminal UI** | Color-coded severity output, spinners, progress bars, tables |
| 📄 **Auto Reports** | Generates Markdown bug bounty reports + JSON data + shell command runbooks |
| 🎮 **Interactive Mode** | Menu-driven interface — no flags needed |
| ⚡ **Multi-threaded** | Configurable thread pool for faster scanning |
| 🔌 **Local Fallback** | Full rule-based chain analysis even without an API key |

---

## 📦 Installation

```bash
# 1. Clone the repo
git clone https://github.com/nishantx4/ghostrecon.git
cd ghostrecon

# 2. Install dependencies
pip install requests

# 3. (Optional) Set your free NVIDIA NIM API key
python ghostrecon.py --set-api nvapi-xxxx

# 4. Run it!
python ghostrecon.py --help
```

> **Note:** Only `requests` is needed — no paid API, no extra SDK.  
> Get a **free** NVIDIA NIM API key at 👉 [build.nvidia.com](https://build.nvidia.com/)

---

## 🔑 API Key Management

GhostRecon uses **NVIDIA NIM** (free tier) — no paid subscriptions needed.

```bash
# Save your key once — it's stored at ~/.ghostrecon/config.json
# The key is auto-tested before saving to make sure it works
python ghostrecon.py --set-api nvapi-xxxx

# Test whether your key is working at any time
python ghostrecon.py --api-test

# Remove the saved key
python ghostrecon.py --remove-api
```

Once saved, the key is automatically loaded on every scan. No need to pass `--api-key` every time.

---

## 🚀 Usage

### Quick Start
```bash
# Basic scan (default modules)
python ghostrecon.py -t example.com

# Full scan — all 14 modules
python ghostrecon.py -t example.com --full

# Interactive mode (guided menu)
python ghostrecon.py --interactive
```

### Pick Your Modules
```bash
python ghostrecon.py -t example.com --modules recon,xss,sqli,idor
```

### All Options
```
NVIDIA AI Key Management:
  --set-api KEY       Save your NVIDIA NIM API key (auto-tests before saving)
  --remove-api        Remove the saved API key
  --api-test          Test whether the saved key is working

Scan Options:
  -t, --target        Target domain (e.g. example.com)
  --api-key KEY       Use a key for this session only (not saved)
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

## 🤖 AI-Powered Hunting (NVIDIA NIM — Free)

Unlike traditional scanners, GhostRecon's AI doesn't just run at the end to generate a report — it actively assists **during** the scan at multiple stages:

### During Recon
- **Endpoint Prioritization** — AI ranks all discovered endpoints by bug bounty value (API routes, user/admin paths, ID parameters, payment flows get promoted to the top)

### During Headers Analysis
- **Risk Chain Assessment** — AI looks at the *combination* of missing headers and explains what real-world attack chains they enable (not just "this header is missing")

### During JavaScript Analysis
- **Deep JS Inspection** — AI reads each JS file and hunts for hidden API routes, client-side auth bypass logic, dangerous function calls (`eval`, `innerHTML`), and obfuscated secrets that regex patterns miss

### During IDOR Testing
- **Smart Response Validation** — AI reads each 200-OK response and determines whether it *actually* leaks private user data, dramatically reducing false positives

### After All Modules Complete
- **Vulnerability Chain Analysis** — AI identifies chains like `SSRF → Credential Exposure → Cloud Takeover`, estimates bounty values per finding, and generates PoC outlines for the top 3 vulnerabilities

> **No API key?** No problem. A built-in local rule-based engine handles chain analysis and prioritization offline.

---

## 📁 Output

Every scan generates three files in `./ghostrecon_output/`:

```
ghostrecon_output/
├── ghostrecon_example.com_20260614_170000.json        ← Raw findings data
├── ghostrecon_example.com_20260614_170000.md           ← Full Markdown report
└── ghostrecon_example.com_20260614_170000_commands.sh  ← Shell command runbook
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
├── ghostrecon.py           ← Entry point, CLI parser, API key management
├── core/
│   ├── config.py           ← Persistent config (~/.ghostrecon/config.json)
│   ├── ai_engine.py        ← NVIDIA NIM AI engine + local fallback
│   ├── banner.py           ← ASCII art banner & startup display
│   ├── session.py          ← Scan orchestrator (runs all modules in order)
│   ├── interactive.py      ← Interactive menu mode
│   ├── findings.py         ← Findings database (deduplication, severity)
│   └── ui.py               ← Terminal colors, spinners, progress bars, tables
└── modules/
    ├── recon.py             ← Crawler & endpoint discovery  [AI: prioritization]
    ├── headers.py           ← Security headers checker      [AI: risk chains]
    ├── js_analysis.py       ← JavaScript secrets scanner    [AI: deep analysis]
    ├── idor.py              ← IDOR detector                 [AI: response validation]
    ├── xss.py               ← XSS detection engine
    ├── sqli.py              ← SQL Injection tester
    ├── cors.py              ← CORS misconfiguration checker
    ├── ssrf.py              ← SSRF prober
    ├── secrets.py           ← Secrets & sensitive file hunter
    ├── nuclei_sim.py        ← Nuclei-style template checks
    ├── graphql.py           ← GraphQL tester
    ├── smuggling.py         ← HTTP Smuggling detector
    ├── params.py            ← Parameter discovery
    └── reporter.py          ← Report generator
```

---

## 🤝 Contributing

Got a module idea, a better payload list, or want to add AI to more modules? PRs are welcome!

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/new-module`)
3. Commit your changes
4. Open a Pull Request

---

<div align="center">

Made with 👻 by **[Nishant](https://github.com/nishantx4)**

Powered by **[NVIDIA NIM](https://build.nvidia.com/)** — free AI inference for everyone

*Happy hunting — and always hack ethically!*

</div>
