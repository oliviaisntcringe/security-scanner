<div align="center">

```
    _   ____      _   ____ _   _ _   _ _____
   / \ |  _ \    / \ / ___| | | | \ | | ____|
  / _ \| |_) |  / _ \ |   | |_| |  \| |  _|
 / ___ \  _ <  / ___ \ |___|  _  | |\  | |___
/_/   \_\_| \_\/_/   \_\____|_| |_|_| \_|_____|
```

### Web Vulnerability Framework

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Version](https://img.shields.io/badge/version-2.0.0-6366f1?style=for-the-badge)](https://github.com/oliviaisntcringe/security-scanner)
[![License](https://img.shields.io/badge/license-MIT-22c55e?style=for-the-badge)](LICENSE)

[![Modules](https://img.shields.io/badge/modules-8-0ea5e9?style=flat-square)](#modules)
[![ML](https://img.shields.io/badge/ML-sklearn-f59e0b?style=flat-square&logo=scikitlearn&logoColor=white)](#ml-detection)
[![Telegram](https://img.shields.io/badge/alerts-Telegram-2CA5E0?style=flat-square&logo=telegram)](https://telegram.org)
[![CLI](https://img.shields.io/badge/console-Metasploit--style-ef4444?style=flat-square)](#console)
[![Web UI](https://img.shields.io/badge/web%20UI-Flask-black?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![Async](https://img.shields.io/badge/async-aiohttp-009688?style=flat-square)](https://docs.aiohttp.org)

> **For authorized security testing only.**  
> Do not scan systems without explicit written permission.

</div>

---

## What is ARACHNE?

ARACHNE (*from Greek mythology — the weaver turned spider*) is a modular web vulnerability framework.  
Like its namesake, it crawls the web and finds what hides in the dark corners of applications.

**Three ways to use it:**

| Interface | Command | Best for |
|-----------|---------|----------|
| 🖥️ **Interactive console** | `arachne console` | Manual testing, exploration |
| ⚡ **One-shot CLI** | `arachne scan <url>` | Scripts, CI pipelines, bulk scans |
| 🌐 **Web dashboard** | `arachne web` | Monitoring, visual reports, team use |

---

## Installation

```bash
git clone https://github.com/oliviaisntcringe/security-scanner.git
cd security-scanner

python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .
```

```bash
arachne --help
```

---

## Console

> Inspired by Metasploit — `use`, `set`, `show options`, `run`, `vulns`, `sessions`

```bash
arachne console
```

```
    _   ____      _   ____ _   _ _   _ _____
   / \ |  _ \    / \ / ___| | | | \ | | ____|
  / _ \| |_) |  / _ \ |   | |_| |  \| |  _|
 / ___ \  _ <  / ___ \ |___|  _  | |\  | |___
/_/   \_\_| \_\/_/   \_\____|_| |_|_| \_|_____|

    v2.0  //  Web Vulnerability Framework  //  MIT License
    Modules: 8  |  ML: enabled  |  Type 'help' for commands

    == use scanner/all     — run all modules
    == set TARGET <url>    — set your target
    == run                 — start scanning


arachne > use sqli
arachne (scanner/sqli) > set TARGET https://example.com
TARGET => https://example.com
arachne (scanner/sqli) > set DEPTH 4
DEPTH => 4
arachne (scanner/sqli) > show options

Module options (scanner/sqli):

   Name       Current Setting      Required  Description
   ----       ---------------      --------  -----------
   TARGET     https://example.com  yes       Target URL to scan
   DEPTH      4                    yes       Crawl depth
   THREADS    5                    yes       Concurrent scan tasks
   TIMEOUT    30                   yes       HTTP timeout (seconds)
   MAX_URLS   50                   yes       Max URLs to test per target
   PROXY                           no        HTTP proxy URL
   FORMAT     html                 yes       Report format: html / json / txt
   ML         true                 yes       Enable ML-based detection
   TELEGRAM   false                no        Send report via Telegram

arachne (scanner/sqli) > run

[*] Module  : scanner/sqli
[*] Target  : https://example.com
[*] Modules : sqli
[*] Depth   : 4  Max-URLs: 50  Threads: 5
[*] ML      : enabled

🔴 SQLI  param=id  url=https://example.com/product?id=1
   payload → ' AND SLEEP(4)--

[+] Scan complete — 1 finding(s) in 11.3s
[*] Report  → reports/arachne_20260521_120000.html  (session #1)

arachne (scanner/sqli) > vulns
arachne (scanner/sqli) > sessions
arachne (scanner/sqli) > report html
arachne (scanner/sqli) > back
arachne >
```

### Console commands

| Command | Description |
|---------|-------------|
| `use <module\|all>` | Select scan module (tab-completable) |
| `set <KEY> <value>` | Set an option |
| `unset <KEY>` | Reset to default |
| `show options` | Current options table |
| `show modules` | List all modules |
| `run` / `exploit` | Start scan |
| `back` | Return to root context |
| `vulns` | All findings from current session |
| `targets` | Scanned hosts + finding counts |
| `sessions` | Scan history |
| `report [html\|json\|txt]` | Generate report |
| `help` / `?` | Help panel |
| `exit` / `quit` | Exit |

---

## CLI

```bash
# All modules, auto-named HTML report
arachne scan https://target.com

# Specific modules
arachne scan https://target.com -m xss,sqli,lfi

# From file, JSON output
arachne scan -f targets.txt --format json -o results.json

# With proxy (Burp Suite etc.)
arachne scan https://target.com --proxy http://127.0.0.1:8080 -v

# Telegram alerts per finding + final report
arachne scan https://target.com --notify-each --telegram

# View / open reports
arachne report --list
arachne report --last
```

### All scan flags

```
arachne scan [OPTIONS] TARGET...

  -f, --file PATH            File with target URLs (one per line)
  -m, --modules TEXT         Modules [default: all]
                             Options: xss sqli ssrf lfi rce csrf cors open_redirect
  -d, --depth INT            Crawl depth  [default: 3]
  -u, --max-urls INT         Max URLs per target  [default: 50]
  -T, --threads INT          Concurrent tasks  [default: 5]
  -t, --timeout INT          HTTP timeout (s)  [default: 30]
      --proxy TEXT           HTTP proxy URL
      --no-ml                Disable ML detection
  -o, --output PATH          Output file (auto-named if omitted)
      --format [html|json|txt]  [default: html]
      --telegram             Send final report via Telegram
      --notify-each          Telegram alert per finding
  -v, --verbose              Verbose output
```

---

## Web Dashboard

```bash
arachne web                          # http://127.0.0.1:5001
arachne web --host 0.0.0.0 --port 8080
```

| Section | Content |
|---------|---------|
| **Dashboard** | Stats cards · Severity doughnut · Type bar chart · Recent findings · Live log |
| **New Scan** | Full form with all options · Progress bar · Real-time Socket.IO output |
| **Vulnerabilities** | Filterable table — Critical / High / Medium / Low |
| **Targets** | All scanned hosts · Finding counts · Rescan button |
| **Reports** | File list · Size · Date · Download link |
| **Settings** | Telegram credentials · Scan defaults · Toggle switches |

All findings stream to the browser in real time via **Socket.IO**.

---

## Modules

| Module | Severity | Detection method |
|--------|----------|-----------------|
| `xss` | 🟠 High | Payload reflection in URL params and forms |
| `sqli` | 🔴 Critical | Error-based · time-based · boolean-based |
| `ssrf` | 🟠 High | Internal hosts · AWS · GCP · Azure metadata |
| `lfi` | 🔴 Critical | Path traversal · PHP wrappers · LFI/RFI |
| `rce` | 🔴 Critical | Command output detection · sleep timing |
| `csrf` | 🟡 Medium | Missing tokens · insecure cookie flags |
| `cors` | 🟡 Medium | Origin reflection · wildcard + credentials |
| `open_redirect` | 🟡 Medium | Unvalidated redirect parameters |

---

## ML Detection

Pre-trained **sklearn** classifiers (`models/*.pkl`) analyse page structure,  
response headers and parameter behaviour to find vulnerabilities that  
payload-based scanning misses.

| Model | Approx. accuracy |
|-------|-----------------|
| XSS   | 85 % |
| SQLi  | 82 % |
| LFI   | 80 % |
| CSRF  | 78 % |
| RCE   | 77 % |
| SSRF  | 75 % |

```bash
# Retrain on fresh data
python generate_training_data.py
python train_ml_models.py

# Disable ML (faster)
arachne scan https://target.com --no-ml
```

---

## Telegram

```bash
# Store once
arachne config --set TELEGRAM_TOKEN=7xxxxxxxxx:AAH...
arachne config --set TELEGRAM_CHAT_ID=123456789

# Or env vars
export TELEGRAM_TOKEN=...
export TELEGRAM_CHAT_ID=...

# Use
arachne scan https://target.com --telegram        # report on completion
arachne scan https://target.com --notify-each     # alert per finding
```

---

## Configuration

Values are read in order: **env var → `~/.arachne.conf` → built-in default**.  
No secrets are stored in the repository.

```bash
arachne config                          # show current config
arachne config --set KEY=VALUE          # write to ~/.arachne.conf
```

| Key | Default | Description |
|-----|---------|-------------|
| `TELEGRAM_TOKEN` | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | — | Telegram chat ID |
| `REQUEST_TIMEOUT` | `30` | HTTP timeout (s) |
| `MAX_CRAWL_DEPTH` | `3` | Crawl depth |
| `MAX_URLS` | `50` | Max URLs per target |
| `CONCURRENT_TASKS` | `5` | Parallel scan tasks |
| `ML_CONFIDENCE_THRESHOLD` | `0.50` | Min confidence for ML findings |

---

## Project Structure

```
security-scanner/
│
├── scanner/                    # Core package
│   ├── cli.py                  # Click CLI entry point  (arachne command)
│   ├── console.py              # Interactive Metasploit-style REPL
│   ├── config.py               # Config: env → ~/.arachne.conf → defaults
│   │
│   ├── core/
│   │   └── orchestrator.py    # Crawl → scan → ML coordinator
│   │
│   ├── scanners/
│   │   ├── base.py            # Async web crawler
│   │   ├── xss.py
│   │   ├── sqli.py
│   │   ├── ssrf.py
│   │   ├── lfi.py
│   │   ├── rce.py
│   │   ├── csrf.py
│   │   ├── cors.py
│   │   └── open_redirect.py
│   │
│   ├── ml/
│   │   └── detector.py        # sklearn model wrapper
│   │
│   └── utils/
│       ├── http.py            # Async HTTP client
│       ├── output.py          # Rich terminal output
│       ├── report.py          # HTML / JSON / txt report generator
│       └── notify.py          # Telegram notifications
│
├── app/                        # Flask web dashboard
│   ├── routes.py
│   ├── templates/index.html   # Single-page dark UI
│   └── static/js/dashboard.js # Socket.IO + Chart.js frontend
│
├── models/                     # Trained ML models (.pkl)
├── exploits/                   # Exploit templates
├── training_data/              # ML training datasets
├── payloads/                   # Fuzzing payload lists
│
├── setup.py
└── requirements.txt
```

---

## Contributing

1. Fork → feature branch → PR
2. One module per scanner file
3. All scan functions: `async def scan(session, url, forms) -> List[Dict]`

---

## License

[MIT](LICENSE)
