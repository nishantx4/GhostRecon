<div align="center">

```
   _____ _               _   _____                     
  / ____| |             | | |  __ \                    
 | |  __| |__   ___  ___| |_| |__) |___  ___ ___  _ __ 
 | | |_ | '_ \ / _ \/ __| __|  _  // _ \/ __/ _ \| '_ \
 | |__| | | | | (_) \__ \ |_| | \ \  __/ (_| (_) | | | |
  \_____|_| |_|\___/|___/\__|_|  \_\___|\___|___/|_| |_|
```

# GhostRecon v3.0 👻

**AI-Powered Bug Bounty Hunter & Vulnerability Scanner**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM%20AI-76B900?style=for-the-badge&logo=nvidia&logoColor=white)](https://build.nvidia.com/)
[![License](https://img.shields.io/badge/License-Proprietary-ef4444?style=for-the-badge)](LICENSE)
[![Made by](https://img.shields.io/badge/Made%20by-Nishant-a855f7?style=for-the-badge)](https://github.com/nishantx4)

*Your personal bug bounty hunting companion — built to make recon smarter, faster, and more fun.*

</div>

---

## 🤔 What is GhostRecon?

GhostRecon v3.0 is a next-generation bug bounty and reconnaissance framework that marries traditional security tooling with an advanced AI verification engine. Built to eliminate false positives and stream execution output live via a **gorgeous Textual Terminal UI (TUI)**, GhostRecon detects **35 different classes of vulnerabilities** and uses **NVIDIA NIM AI (free tier)** to actively *help during the hunt itself*.

Think of it as your personal ghost that haunts a target, validates findings to eliminate noise, and reports back everything it finds in real time. 👻

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎨 **Gorgeous Textual TUI** | Fully asynchronous 3-panel interactive dashboard with live log streaming. |
| 🛡️ **35 Scan Modules** | SQLi, XSS, XXE, Command Injection, Prototype Pollution, IDOR, GraphQL, Smuggling, etc. |
| 🤖 **NVIDIA NIM AI** | Free-tier AI that validates findings and reads DOM structures to reduce false positives. |
| 🧠 **Phase 0 Baseline** | Fingerprints WAFs, SPAs, calculates network jitter, and diffs Soft-404 error pages. |
| ⚡ **External Tool Pipeline** | Automatically pipes targets through `subfinder`, `katana`, `nuclei`, streaming straight to the TUI. |
| 🔑 **Persistent API Key** | Set once with `--set-api`, automatically used on every scan. |
| 📄 **Auto Reports** | Generates Markdown bug bounty reports + JSON data + shell command runbooks. |
| 🔌 **Local Fallback** | Full native Python engines if external tools or API keys are unavailable. |

---

## 📦 Installation

```bash
# 1. Clone the repo
git clone https://github.com/nishantx4/ghostrecon.git
cd ghostrecon

# 2. Install dependencies (poetry or pip)
pip install -r requirements.txt

# 3. (Optional) Set your free NVIDIA NIM API key
python ghostrecon.py --set-api nvapi-xxxx

# 4. Run it!
python ghostrecon.py --help
```

> **Note:** Get a **free** NVIDIA NIM API key at 👉 [build.nvidia.com](https://build.nvidia.com/)

---

## 🔑 API Key Management

```bash
# Save your key once — it's stored at ~/.ghostrecon/config.json
# The key is auto-tested before saving to make sure it works
python ghostrecon.py --set-api nvapi-xxxx

# Test whether your key is working at any time
python ghostrecon.py --api-test

# Remove the saved key
python ghostrecon.py --remove-api
```

---

## 🚀 Usage

GhostRecon is invoked via `ghostrecon.py`. By default, if a target is provided, it launches the interactive Textual Dashboard.

### Quick Start
```bash
# Basic scan
python ghostrecon.py -t example.com

# Quick profile (Recon, CMS, Headers, Secrets, CORS, Nuclei)
python ghostrecon.py -t example.com --preset quick

# Full profile (Runs all 35 modules, extremely thorough and loud)
python ghostrecon.py -t example.com --preset full
```

### Pick Your Modules
```bash
python ghostrecon.py -t example.com --modules xss,graphql,sqli
```

### Legacy Headless & Output Flags
```bash
# Disable the TUI and run as standard stdout CLI (Useful for CI/CD)
python ghostrecon.py -t example.com --no-tui

# Save report output to a specific directory
python ghostrecon.py -t example.com --output-dir ./my_reports/
```

---

## 🤖 AI-Powered Hunting (NVIDIA NIM — Free)

Unlike traditional scanners, GhostRecon's AI doesn't just run at the end to generate a report — it actively assists **during** the scan at multiple stages:
- **Baseline Profiling** to drastically reduce blind false positives.
- **Deep JS Inspection** to hunt for hidden API routes and obfuscated secrets.
- **Smart Response Validation** to read 200-OK responses and determine if they *actually* leak private data.
- **Vulnerability Chain Analysis** to estimate bounty values and generate PoC outlines.

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

## 📜 License

This software is released under a **Proprietary License**. 
You are permitted to use this tool for personal, educational, or internal business purposes, but you may NOT modify, redistribute, or reverse-engineer the code. See the `LICENSE` file for full details.

---

<div align="center">

Made with 👻 by **[Nishant](https://github.com/nishantx4)**

Powered by **[NVIDIA NIM](https://build.nvidia.com/)** — free AI inference for everyone

*Happy hunting — and always hack ethically!*

</div>
