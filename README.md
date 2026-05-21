<div align="center">

<pre>
 __   ___   _ _     _   _ ____   ____    _    _   _
 \ \ / / | | | |   | \ | / ___| / ___|  / \  | \ | |
  \ V /| | | | |   |  \| \___ \| |     / _ \ |  \| |
   | | | |_| | |___| |\  |___) | |___ / ___ \| |\  |
   |_|  \___/|_____|_| \_|____/ \____/_/   \_\_| \_|
</pre>

# VulnScan

**Web vulnerability scanner — CLI-first, ML-enhanced, Metasploit-style console**

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)](https://github.com/oliviaisntcringe/security-scanner/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-8-6366f1?style=flat-square)](#modules)
[![ML](https://img.shields.io/badge/ML-sklearn-f59e0b?style=flat-square&logo=scikitlearn&logoColor=white)](#ml-detection)
[![Telegram](https://img.shields.io/badge/Telegram-notifications-2CA5E0?style=flat-square&logo=telegram&logoColor=white)](#telegram)
[![Flask](https://img.shields.io/badge/Web%20UI-Flask-000000?style=flat-square&logo=flask&logoColor=white)](#web-dashboard)
[![Status](https://img.shields.io/badge/status-active-brightgreen?style=flat-square)]()

> ⚠️ **For authorized security testing only.** Do not scan systems you don't own or have explicit written permission to test.

</div>

---

## Overview

VulnScan is a modular web vulnerability scanner with three interfaces:

| Interface | Command | Description |
|-----------|---------|-------------|
| **Interactive console** | `vulnscan console` | Metasploit-style REPL with tab completion |
| **One-shot CLI** | `vulnscan scan <url>` | Scriptable, CI-friendly |
| **Web dashboard** | `vulnscan web` | Dark real-time Flask UI |

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Console (Metasploit-style)](#console-metasploit-style)
- [CLI Usage](#cli-usage)
- [Web Dashboard](#web-dashboard)
- [Modules](#modules)
- [ML Detection](#ml-detection)
- [Telegram](#telegram)
- [Configuration](#configuration)
- [Project Structure](#project-structure)

---

## Features

- **8 scan modules** — XSS, SQLi, SSRF, LFI/RFI, RCE, CSRF, CORS, Open Redirect
- **ML detection** — sklearn models trained on real vulnerability patterns
- **Interactive console** — `use`, `set`, `show options`, `run`, `vulns`, `sessions` like msfconsole
- **Smart deduplication** — findings grouped by `(base_url, type, parameter)`, no noise
- **Rich output** — colored tables, severity badges, progress indicators
- **3 report formats** — HTML, JSON, plain text
- **Telegram alerts** — per-finding in real time or full report on scan complete
- **Web dashboard** — real-time Socket.IO updates, charts, target management
- **Zero hardcoded secrets** — all credentials via env vars or `~/.vulnscan.conf`

---

## Installation

```bash
git clone https://github.com/oliviaisntcringe/security-scanner.git
cd security-scanner

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

pip install -e .
```

Verify:

```bash
vulnscan --help
```

---

## Console (Metasploit-style)

```bash
vulnscan console
```

```
 __   ___   _ _     _   _ ____   ____    _    _   _
 \ \ / / | | | |   | \ | / ___| / ___|  / \  | \ | |
  ...

vulnscan > use sqli
vulnscan (scanner/sqli) > set TARGET https://example.com
TARGET => https://example.com
vulnscan (scanner/sqli) > set DEPTH 3
DEPTH => 3
vulnscan (scanner/sqli) > show options

Module options (scanner/sqli):

   Name       Current Setting     Required  Description
   ----       ---------------     --------  -----------
   TARGET     https://example     yes       Target URL to scan
   DEPTH      3                   yes       Crawl depth
   THREADS    5                   yes       Concurrent scan tasks
   TIMEOUT    30                  yes       HTTP timeout (seconds)
   MAX_URLS   50                  yes       Max URLs to test per target
   PROXY                          no        HTTP proxy
   FORMAT     html                yes       Report format: html / json / txt
   ML         true                yes       Enable ML-based detection
   TELEGRAM   false               no        Send report via Telegram

vulnscan (scanner/sqli) > run

[*] Module  : scanner/sqli
[*] Target  : https://example.com
[*] Depth   : 3  Max-URLs: 50  Threads: 5

🔴 SQLI  param=id  url=https://example.com/item?id=1
   payload → ' AND SLEEP(4)--

[+] Scan complete — 1 finding(s) in 12.4s

[*] Report  → /path/to/reports/vulnscan_20260521_120000.html  (session #1)
```

### Console commands

| Command | Description |
|---------|-------------|
| `use <module\|all>` | Select scan module |
| `set <KEY> <value>` | Set an option (tab-completable) |
| `unset <KEY>` | Reset to default |
| `show options` | Display current options table |
| `show modules` | List all available modules |
| `run` / `exploit` | Start the scan |
| `back` | Deselect current module |
| `vulns` | Show all vulnerabilities from current session |
| `targets` | List scanned targets |
| `sessions` | Show completed scan history |
| `report [html\|json\|txt]` | Generate report from all sessions |
| `help` / `?` | Show help panel |
| `exit` / `quit` | Exit console |

---

## CLI Usage

### Basic

```bash
# Scan with all modules, HTML report
vulnscan scan https://target.com

# Specific modules
vulnscan scan https://target.com -m xss,sqli,lfi

# Multiple targets from file
vulnscan scan -f targets.txt --format json -o results.json

# Verbose + proxy (e.g. Burp Suite)
vulnscan scan https://target.com -v --proxy http://127.0.0.1:8080
```

### All options

```
vulnscan scan [OPTIONS] TARGET...

  -f, --file PATH            File with target URLs (one per line)
  -m, --modules TEXT         Modules to run [default: all]
                             Available: xss, sqli, ssrf, lfi, rce,
                                        csrf, cors, open_redirect
  -d, --depth INT            Crawl depth  [default: 3]
  -u, --max-urls INT         Max URLs per target  [default: 50]
  -T, --threads INT          Concurrent tasks  [default: 5]
  -t, --timeout INT          HTTP timeout in seconds  [default: 30]
  --proxy TEXT               HTTP proxy URL
  --no-ml                    Disable ML detection
  -o, --output PATH          Output file (auto-named if omitted)
  --format [html|json|txt]   Report format  [default: html]
  --telegram                 Send final report via Telegram
  --notify-each              Telegram alert per finding (real-time)
  -v, --verbose              Verbose output
```

### Report & Config

```bash
vulnscan report --list          # list all saved reports
vulnscan report --last          # open latest report in browser

vulnscan config                 # show current config
vulnscan config --set TELEGRAM_TOKEN=xxx
vulnscan config --set TELEGRAM_CHAT_ID=xxx
```

---

## Web Dashboard

```bash
vulnscan web                            # http://127.0.0.1:5001
vulnscan web --host 0.0.0.0 --port 8080
```

### Dashboard sections

| Section | Description |
|---------|-------------|
| **Dashboard** | Stats cards, severity doughnut chart, vuln-type bar chart, recent findings, live log |
| **New Scan** | Full scan form with all options, real-time progress bar and live output |
| **Vulnerabilities** | Filterable table by severity (Critical / High / Medium / Low) |
| **Targets** | All scanned hosts, finding count, Rescan button |
| **Reports** | Generated report files with download links |
| **Settings** | Telegram credentials, scan defaults, toggle switches |

All findings stream to the browser in real time via Socket.IO.

---

## Modules

| Name | Severity | Detects |
|------|----------|---------|
| `xss` | 🟠 High | Reflected XSS in URL params and forms; DOM sink hints |
| `sqli` | 🔴 Critical | Error-based, time-based, boolean-based SQL injection |
| `ssrf` | 🟠 High | Internal service access, AWS / GCP metadata endpoints |
| `lfi` | 🔴 Critical | Local File Inclusion, Remote File Inclusion, path traversal |
| `rce` | 🔴 Critical | OS command injection — output-based and time-based |
| `csrf` | 🟡 Medium | Missing anti-CSRF tokens, insecure cookie flags |
| `cors` | 🟡 Medium | Origin reflection, wildcard + credentials misconfiguration |
| `open_redirect` | 🟡 Medium | Unvalidated redirect parameters |

---

## ML Detection

Pre-trained **sklearn** models (`models/*.pkl`) detect vulnerability patterns from page structure, response headers, and parameter behaviour — catching issues that payload-based scanners miss.

```bash
# Disable ML (faster scans)
vulnscan scan https://target.com --no-ml

# Retrain models on fresh data
python generate_training_data.py
python train_ml_models.py
```

Detection accuracy (pre-trained models):

| Model | Accuracy |
|-------|----------|
| XSS   | ~85 % |
| SQLi  | ~82 % |
| CSRF  | ~78 % |
| SSRF  | ~75 % |
| LFI   | ~80 % |
| RCE   | ~77 % |

---

## Telegram

```bash
# Store credentials (written to ~/.vulnscan.conf)
vulnscan config --set TELEGRAM_TOKEN=7xxxxxxxxx:AAH...
vulnscan config --set TELEGRAM_CHAT_ID=123456789

# Or export as env vars
export TELEGRAM_TOKEN=...
export TELEGRAM_CHAT_ID=...

# Send full report at end of scan
vulnscan scan https://target.com --telegram

# Alert on every finding in real time
vulnscan scan https://target.com --notify-each
```

---

## Configuration

All values read from **environment variables** first, then `~/.vulnscan.conf`, then built-in defaults. No secrets are ever committed to the repository.

| Key | Default | Description |
|-----|---------|-------------|
| `TELEGRAM_TOKEN` | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | — | Telegram chat / channel ID |
| `REQUEST_TIMEOUT` | `30` | HTTP timeout in seconds |
| `MAX_CRAWL_DEPTH` | `3` | Default crawl depth |
| `MAX_URLS` | `50` | Max URLs per target |
| `CONCURRENT_TASKS` | `5` | Parallel scan tasks |
| `ML_CONFIDENCE_THRESHOLD` | `0.50` | Minimum ML confidence to report |

```bash
# View all current values
vulnscan config
```

---

## Project Structure

```
security-scanner/
├── scanner/                    # CLI package
│   ├── cli.py                  # Click entry point
│   ├── console.py              # Metasploit-style interactive console
│   ├── config.py               # Env-var / file based config
│   ├── core/
│   │   └── orchestrator.py     # Crawl + scan coordinator
│   ├── scanners/
│   │   ├── base.py             # Async web crawler
│   │   ├── xss.py
│   │   ├── sqli.py
│   │   ├── ssrf.py
│   │   ├── lfi.py
│   │   ├── rce.py
│   │   ├── csrf.py
│   │   ├── cors.py
│   │   └── open_redirect.py
│   ├── ml/
│   │   └── detector.py         # ML wrapper (sklearn)
│   └── utils/
│       ├── http.py             # Async HTTP client
│       ├── output.py           # Rich terminal output
│       ├── report.py           # HTML / JSON / txt reports
│       └── notify.py           # Telegram notifications
│
├── app/                        # Flask web dashboard
│   ├── routes.py               # API + page routes
│   ├── templates/index.html    # Single-page dashboard
│   └── static/js/dashboard.js # Socket.IO + Chart.js frontend
│
├── models/                     # Trained ML models (.pkl)
├── exploits/                   # Exploit templates
├── training_data/              # ML training datasets
├── payloads/                   # Fuzzing payload lists
│
├── setup.py                    # pip install -e .
└── requirements.txt
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes
4. Open a Pull Request

---

## License

[MIT](LICENSE) — for **authorized** security testing only.
