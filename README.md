<div align="center">

```
███╗   ███╗███████╗██╗  ██╗██╗   ██╗███╗  ██╗████████╗███████╗██████╗
████╗ ████║╚════██║██║  ██║██║   ██║████╗ ██║╚══██╔══╝██╔════╝██╔══██╗
██╔████╔██║    ██╔╝███████║██║   ██║██╔██╗██║   ██║   █████╗  ██████╔╝
██║╚██╔╝██║   ██╔╝ ██╔══██║╚██╗ ██╔╝██║╚████║   ██║   ██╔══╝  ██╔══██╗
██║ ╚═╝ ██║   ██║  ██║  ██║ ╚████╔╝ ██║ ╚███║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝   ╚═╝  ╚═╝  ╚═╝  ╚═══╝  ╚═╝  ╚══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

**M7Hunter V7.0 — MilkyWay Hunter**

*Professional Bug Bounty Automation Framework*

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/Vuln_Modules-28-red?style=flat-square)]()
[![Version](https://img.shields.io/badge/Version-7.0-cyan?style=flat-square)]()

> Plugin-driven · HTTP/2 · CEO Engine · Double-Verify · AI-Assisted · Live Dashboard

</div>

---

## ⚡ What is M7Hunter?

M7Hunter is a **production-grade, fully automated bug bounty reconnaissance and vulnerability discovery framework** built for serious security researchers. It chains 28 specialized engines in an intelligent parallel pipeline — from subdomain discovery to complex logic bug detection — and delivers detailed, report-ready findings.

**Not another script kiddie tool.** Every finding goes through a CEO rule engine, confidence scoring, and optional double-verification before appearing in your report.

---

## 🚀 Features

| Category | Capability |
|----------|-----------|
| **Recon** | Subfinder + Amass + assetfinder + crt.sh · DNS · HTTP probe · Port scan |
| **Crawling** | Katana + GAU + Wayback + SPA JS crawler (Playwright/React/Vue/Next) |
| **Injection** | SQLi · XSS (dalfox) · SSTI · NoSQL · XXE · LFI · SSRF |
| **Logic Bugs** | IDOR + multi-session · CSRF · Race conditions (async HTTP/2) · CORS |
| **Auth** | JWT alg:none · JWT weak secret · Host header injection · OAuth flows |
| **Cloud** | AWS S3 open buckets · Azure Blob · GCP Firebase · Cloud metadata SSRF |
| **Infrastructure** | HTTP Smuggling (CL.TE/TE.CL) · Subdomain takeover · WebSocket injection |
| **Modern** | GraphQL introspection · Prototype pollution · WordPress scanning |
| **Secrets** | GitHub dorks · JS file secrets (TruffleHog) · .env exposure |
| **AI** | Ollama-powered analysis · False-positive reduction · Chain suggestions |
| **Dashboard** | Real-time live dashboard · Findings stream · AI chat · Export |
| **Reporting** | HTML · Markdown (HackerOne ready) · JSON · Burp XML |

---

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/httpsm7/m7hunter
cd m7hunter
sudo bash install.sh
```

### Docker (Zero-Dependency)

```bash
docker build -t m7hunter .
docker run --rm -it m7hunter -u target.com --deep
```

### Manual Python Setup

```bash
git clone https://github.com/httpsm7/m7hunter
cd m7hunter
pip3 install -r requirements.txt
playwright install chromium
sudo python3 m7hunter.py --check
```

### Requirements

- Python 3.11+
- Root / sudo (for nmap, masscan)
- Linux / macOS (Kali, Ubuntu, Parrot recommended)

---

## 🎯 Usage

### Basic Scans

```bash
# Fast scan — Phase 1 only (recon + critical vulns)
sudo python3 m7hunter.py -u target.com --fast

# Deep scan — all 28 modules
sudo python3 m7hunter.py -u target.com --deep

# Authenticated scan
sudo python3 m7hunter.py -u target.com --deep --cookie "session=abc123"

# IDOR multi-session (attacker + victim accounts)
sudo python3 m7hunter.py -u target.com --deep --userA "sess_a=x" --userB "sess_b=y"
```

### Advanced Usage

```bash
# Stealth mode (Tor + slow delays)
sudo python3 m7hunter.py -u target.com --stealth

# Custom modules only
sudo python3 m7hunter.py -u target.com --custom --xss --sqli --idor --cors

# Multiple targets from file
sudo python3 m7hunter.py -f targets.txt --deep

# With scope enforcement
sudo python3 m7hunter.py -u target.com --deep --scope scope.txt

# Resume interrupted scan
sudo python3 m7hunter.py -u target.com --deep --resume

# With Telegram notifications
sudo python3 m7hunter.py -u target.com --deep \
  --telegram-token "BOT_TOKEN" --telegram-chat "CHAT_ID"

# Continuous monitoring mode
sudo python3 m7hunter.py -u target.com --continuous --interval 3600
```

### Dashboard

```bash
# Standalone dashboard (view previous results)
python3 m7hunter.py --dashboard --dashboard-port 8719

# Dashboard starts automatically during any scan at:
# http://localhost:8719
```

### Tool Management

```bash
# Install all dependencies
sudo python3 m7hunter.py --install

# Check installed tools
python3 m7hunter.py --check

# Update all tools + nuclei templates
sudo python3 m7hunter.py --update
```

---

## 🏗️ Architecture

```
m7hunter/
├── m7hunter.py              # CLI entry point
├── core/
│   ├── pipeline_v7.py       # Main pipeline orchestrator (CEO-driven)
│   ├── ceo_engine.py        # Rule engine: gate, dedup, chain, verify
│   ├── plugin_loader.py     # Auto-discovery of step modules
│   ├── findings_engine.py   # Thread-safe finding registry
│   ├── session_manager.py   # Multi-session auth (IDOR userA/userB)
│   ├── http_client.py       # HTTP/2 async client (httpx)
│   ├── installer.py         # Tool installer/checker
│   └── ...
├── modules/                 # 28 step modules (step01–step28)
│   ├── step01_subdomain.py
│   ├── step06_nuclei.py
│   └── ... (step02–step28)
├── engines/                 # Specialized vuln engines
│   ├── race_engine_v7.py    # Async HTTP/2 race conditions
│   ├── idor_engine.py       # IDOR + multi-session
│   ├── xss_engine.py        # XSS detection
│   ├── double_verify.py     # False-positive reduction
│   └── ...
├── ai/                      # AI integration
│   ├── offline_ai.py        # Offline pattern-based AI
│   └── secure_db.py         # Encrypted AI brain DB
├── integrations/
│   └── ollama_ai.py         # Ollama LLM integration
├── web/
│   ├── server.py            # Dashboard HTTP server
│   └── static/index.html   # Premium dark UI dashboard
├── reporting/
│   └── report_generator.py # HTML/MD/JSON/Burp reports
├── templates/nuclei/
│   └── m7-custom/          # Custom nuclei templates
└── config/
    └── m7hunter.yaml        # Default configuration
```

### Pipeline Flow

```
Target
  └─► Subdomain Enum → DNS Resolve → HTTP Probe → Port Scan
                                         │
                          ┌──────────────┴──────────────────┐
                          │        PHASE 1 (parallel)        │
                          │  nuclei · XSS · SSRF · IDOR      │
                          │  takeover · GitHub · CSRF         │
                          └──────────────┬──────────────────┘
                                         │
                          ┌──────────────┴──────────────────┐
                          │        PHASE 2 (parallel)        │
                          │  SQLi · CORS · LFI · SSTI · JWT  │
                          │  GraphQL · Smuggling · Race · ... │
                          └──────────────┬──────────────────┘
                                         │
                              CEO Engine (gate/dedup/verify)
                                         │
                              FindingsEngine (register)
                                         │
                              Report Generator (HTML/MD/JSON)
```

---

## 🛡️ Vulnerability Coverage

| Module | Bugs Found | Severity |
|--------|-----------|---------|
| Subdomain Takeover | dangling CNAME, NS, A records | Critical |
| SQLi | boolean, time-based, error-based | Critical |
| SSRF | AWS/GCP/Azure metadata, internal | Critical |
| IDOR | UUID, numeric ID, multi-session ATO | Critical/High |
| LFI | /etc/passwd, keys, .env | Critical/High |
| XSS | reflected, stored, DOM | High |
| CORS | ACAO reflection, null origin | High |
| JWT | alg:none, weak secret, no expiry | Critical/High |
| HTTP Smuggling | CL.TE, TE.CL, TE.TE | Critical |
| Race Conditions | transfer doubling, vote stuffing | Critical/High |
| GraphQL | introspection, batching, injection | Medium/High |
| CSRF | missing token, SameSite:None | High/Medium |
| Host Header | password reset poisoning, SSRF | High |
| SSTI | Python/Ruby/Java template injection | Critical |
| NoSQL | MongoDB auth bypass, injection | Critical/High |
| XXE | file read, SSRF via XML | Critical |
| Proto Pollution | JS prototype chain pollution | Medium |
| WebSocket | injection, CSWSH, hijacking | High |
| Cloud | S3 open, Firebase, Azure Blob | Critical/High |

---

## ⚙️ Configuration

Edit `config/m7hunter.yaml` or `~/.m7hunter.yaml`:

```yaml
threads: 50
rate: 1000
confidence: 0.8
double_verify: true
output_dir: results

# API Keys (use env vars recommended)
# github_token: "ghp_xxx"
# shodan_key: "xxx"
```

Or pass everything via CLI flags. CLI always takes precedence over config file.

---

## 📊 Sample Report Output

```
[CRITICAL] SSRF_AWS         → https://api.target.com/fetch?url=...
[CRITICAL] LFI_UNIX_PASSWD  → https://target.com/read?file=...
[HIGH]     IDOR_CONFIRMED   → https://api.target.com/users/1337
[HIGH]     CORS_MISCONFIG   → https://target.com/api/data
[MEDIUM]   OPEN_REDIRECT    → https://target.com/go?to=...

════════════════════════════════════════
  ✅ PIPELINE COMPLETE — target.com
  ⏱  Time     : 847s (14.1 min)
  🚨 Findings : 12 total | CRIT:3 HIGH:5 MED:4 LOW:0
  📊 Report   : results/tar_20260516_143022_v7/tar_report.html
════════════════════════════════════════
```

---

## 🔧 Changelog

### V7.0 (2026-05-16)
- Plugin-driven architecture (auto-discover modules)
- CEO Engine: live gate, dedup, auto-chain
- Double-Verify: FP reduction for critical/high findings
- SPA Crawler: Playwright headless for React/Vue/Next apps
- HTTP/2 via httpx for concurrent requests
- Async Race Condition Engine (HTTP/2 parallel floods)
- WebSocket injection engine
- Prototype pollution engine
- Multi-session IDOR (--userA / --userB)
- FindingsEngine: centralized thread-safe registry (fixes "0 findings" bug)
- Premium live dashboard with real-time polling
- Burp XML + HTML + Markdown + JSON reports
- Telegram + Discord notifications
- Ollama AI integration (local LLM)
- 7 high-quality custom nuclei templates

---

## 🤝 Contributing

1. Fork the repo
2. Create feature branch: `git checkout -b feature/your-engine`
3. Follow the plugin pattern: class `StepXxName` with `run(self)` method
4. Submit PR with description of what bugs it catches

---

## ⚖️ Legal Disclaimer

**This tool is for authorized security testing ONLY.**

- Only use on systems you own or have explicit written permission to test
- Bug bounty programs within their defined scope
- Penetration testing engagements with signed authorization
- Private lab environments

**Unauthorized scanning is illegal under the CFAA, Computer Misuse Act, and equivalent laws worldwide. The author and MilkyWay Intelligence accept no liability for misuse.**

---

<div align="center">

Made with ❤️ by **Sharlix** | **MilkyWay Intelligence**

`bug bounty automation` · `recon` · `vulnerability scanner` · `pentesting` · `nuclei` · `subdomain enumeration`

</div>
