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

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![NVIDIA NIM](https://img.shields.io/badge/NVIDIA-NIM%20AI-76B900?style=for-the-badge&logo=nvidia&logoColor=white)](https://build.nvidia.com/)
[![License](https://img.shields.io/badge/License-Proprietary-ef4444?style=for-the-badge)](LICENSE)
[![Made by](https://img.shields.io/badge/Made%20by-Nishant-a855f7?style=for-the-badge)](https://github.com/nishantx4)

*Your personal bug bounty hunting companion — built to make recon smarter, faster, and more fun.*

</div>

---

## 🤔 What is GhostRecon?

GhostRecon v3.0 is a next-generation bug bounty and reconnaissance framework that marries traditional security tooling with an AI verification engine and a multi-stage statistical validator built to eliminate false positives. It detects **35 classes of vulnerabilities**, discovers and tests **pure JSON/XML REST APIs** (not just crawlable HTML sites), and can **propagate a live session across the whole scan** — so an auth-bypass found in one module is automatically reused by every module that runs after it, reaching authenticated-only endpoints that a stateless scanner would never see.

Think of it as your personal ghost that haunts a target, validates findings to eliminate noise, and reports back everything it finds in real time. 👻

---

## ✨ Features

| Feature | Description |
|---|---|
| 🎨 **Gorgeous Textual TUI** | Interactive 3-panel dashboard with a live module checklist (all 35 modules, driven by Quick/Standard/Full presets), live log streaming, and AI activity feed. |
| 🛡️ **35 Scan Modules** | SQLi, NoSQL Injection, XSS, XXE, SSTI, LFI/Path Traversal, Command Injection, Prototype Pollution, Deserialization, IDOR, JWT attacks, Broken Auth, OAuth, Mass Assignment, GraphQL, HTTP Smuggling, Cache Poisoning, Host Header Injection, and more. |
| 🌐 **OpenAPI/Swagger-aware** | Auto-discovers and parses `/openapi.json`, `/swagger.json`, etc. Every injection module can then test real JSON body properties, XML bodies, and URL path parameters — not just HTML forms and query strings. This is what lets GhostRecon find bugs on pure REST APIs that have zero crawlable HTML. |
| 🔑 **Live credential propagation** | When any module discovers a working credential — an auth-bypass SQLi that returns a real session token, a forged JWT the server accepts — it's captured automatically and reused by every module that runs afterward. Combine with `--header`/`--cookie` to seed your own session and scan authenticated areas end to end. |
| 🧠 **Multi-stage Validator engine** | Differential (true/false/control) testing, Z-score statistical timing analysis, JSON-shape-aware structural diffing, DOM-context-aware reflection analysis, and AI semantic verification — all reusable by any module, not duplicated ad hoc per module. |
| 🤖 **NVIDIA NIM AI** | Free-tier AI that suggests payloads, validates findings, reads JS for hidden endpoints/secrets, and produces a full vulnerability-chain analysis with bounty estimates at the end of a scan. |
| 🧬 **Phase 0 Baseline** | Fingerprints WAFs, SPAs, calculates network jitter, and diffs soft-404 error pages before any module runs. |
| ⚡ **External Tool Pipeline** | Auto-installs and runs `subfinder`, `katana`, `waybackurls`, and a full-template `nuclei` scan, streaming results straight into the TUI. |
| 🔓 **Active exploitation, not just static checks** | e.g. `jwt.py` forges an `alg:none` token and a weak-HMAC-secret token and actually submits them to the live endpoint rather than just flagging "weak JWT config" from inspection alone. |
| 📄 **Auto Reports** | Generates Markdown bug bounty reports (with evidence, confidence scores, and validation steps per finding) + JSON data + shell command runbooks. |
| 🔌 **Local Fallback** | Full native Python engines if external tools or an API key aren't available — nothing hard-requires the AI or Go tools to work. |

---

## 📦 Installation

```bash
# 1. Clone the repo
git clone https://github.com/nishantx4/ghostrecon.git
cd ghostrecon

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Set your free NVIDIA NIM API key
python ghostrecon.py --set-api nvapi-xxxx

# 4. Run it!
python ghostrecon.py --help
```

> **Note:** Get a **free** NVIDIA NIM API key at 👉 [build.nvidia.com](https://build.nvidia.com/)

External tools (`subfinder`, `katana`, `waybackurls`, `nuclei`) are downloaded automatically into `~/.ghostrecon/tools/bin` on first use — no Go toolchain or manual install needed. Pass `--no-auto-install` to disable this.

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

GhostRecon is invoked via `ghostrecon.py`. By default, if a target is provided (or not — you'll get a setup screen), it launches the interactive Textual Dashboard.

### Quick Start
```bash
# Basic scan
python ghostrecon.py -t example.com

# Quick profile (Recon, CMS, Headers, Secrets, CORS, Nuclei)
python ghostrecon.py -t example.com --preset quick

# Standard profile (the sensible default set — recon, sqli, xss, ssrf, lfi, idor, ...)
python ghostrecon.py -t example.com --preset standard

# Full profile (all 35 modules — thorough and loud)
python ghostrecon.py -t example.com --preset full
```

### Pick Your Modules
```bash
python ghostrecon.py -t example.com --modules xss,graphql,sqli,lfi
```

### Scan Authenticated Areas
```bash
# Supply your own session so gated endpoints get tested too
python ghostrecon.py -t example.com --header "X-Auth-Token: abc123" --cookie "session=abc123"

# Repeat --header/--cookie as needed — every module (and the OpenAPI parser) uses them
python ghostrecon.py -t example.com --header "Authorization: Bearer abc123" --header "X-Api-Version: 2"
```
If a module discovers a *working* credential mid-scan (e.g. an auth-bypass SQLi that returns a live token), it's captured and propagated automatically too — you don't have to already know it works.

### Legacy Headless & Output Flags
```bash
# Disable the TUI and run as standard stdout CLI (useful for CI/CD)
python ghostrecon.py -t example.com --no-tui

# Save report output to a specific directory
python ghostrecon.py -t example.com --output-dir ./my_reports/

# Skip auto-installing external tools
python ghostrecon.py -t example.com --no-auto-install
```

---

## 🌐 REST API Awareness

Most scanners only find what they can crawl — a pure JSON/XML REST API with zero HTML forms is invisible to them. GhostRecon actively looks for an OpenAPI/Swagger spec (`/openapi.json`, `/openapi.yaml`, `/swagger.json`, `/v3/api-docs`, and a dozen other common locations) and, when found, parses every operation into structured test targets: JSON body properties, XML body fields (with the real discovered example body, not a guessed envelope), URL path parameters, and required auth headers. Every injection module (SQLi, NoSQL, XSS, SSTI, XXE, LFI, SSRF, Prototype Pollution, Mass Assignment, Open Redirect, ...) consumes this automatically, so a modern API-first target gets the same depth of testing as a classic HTML site.

---

## 🔗 Live Credential Propagation

Most scanners test every endpoint unauthenticated, in isolation, one shot each. GhostRecon keeps state across the whole scan:

1. Supply a known-good credential yourself with `--header`/`--cookie` (or the TUI's "Auth Header" field), **or**
2. Let a module find one — e.g. `sqli.py` confirms an auth-bypass SQL injection on a login endpoint and the response contains a real session token,

...and from that point on, every module that runs afterward automatically attaches that credential to its own requests. An auth-bypass discovered ten minutes into a scan can unlock IDOR, mass-assignment, and broken-auth testing on endpoints that were returning 401 the whole time before that.

---

## 🤖 AI-Powered Hunting (NVIDIA NIM — Free)

Unlike traditional scanners, GhostRecon's AI doesn't just run at the end to generate a report — it actively assists **during** the scan at multiple stages:
- **Baseline Profiling** to drastically reduce blind false positives.
- **Deep JS Inspection** to hunt for hidden API routes and obfuscated secrets.
- **Smart Response Validation** to read 200-OK responses and determine if they *actually* leak private data, and to distinguish a real secret from a placeholder/example value.
- **Vulnerability Chain Analysis** to identify how individual findings combine into a bigger attack path, estimate bounty values, and generate PoC outlines.

Every finding also carries a `confidence` label, a numeric `confidence_score`, and the list of `validation_steps` that produced it, so you can tell at a glance which findings are differential/statistically confirmed versus heuristic.

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
