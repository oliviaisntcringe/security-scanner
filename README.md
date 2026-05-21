# VulnScan

<div align="center">

[![Python](https://img.shields.io/badge/Python-3.9%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-v2.0-brightgreen?style=flat-square)]()

**Web vulnerability scanner — CLI-first, ML-enhanced.**

> For authorized security testing only.

</div>

---

## Features

| Module | Detects |
|--------|---------|
| `xss` | Reflected XSS (URL params + forms), DOM sink hints |
| `sqli` | Error-based, time-based, boolean-based SQL injection |
| `ssrf` | Internal service access, AWS/GCP metadata endpoints |
| `lfi` | Local/Remote File Inclusion, path traversal |
| `rce` | OS command injection (output + time-based) |
| `csrf` | Missing tokens, insecure cookie flags |
| `cors` | Origin reflection, wildcard + credentials misconfigs |
| `open_redirect` | Unvalidated redirects in URL parameters |
| `ml` | Sklearn-based anomaly detection across all vuln types |

---

## Installation

```bash
git clone https://github.com/oliviaisntcringe/security-scanner.git
cd security-scanner

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e .
```

---

## Quick start

```bash
# Scan a single target (all modules, HTML report)
vulnscan scan https://example.com

# Specific modules only
vulnscan scan https://example.com -m xss,sqli,lfi

# Multiple targets from file
vulnscan scan -f targets.txt --format json -o results.json

# Real-time Telegram alerts + final report
vulnscan scan https://example.com --notify-each --telegram

# With proxy, increased depth
vulnscan scan https://example.com -d 4 -u 100 --proxy http://127.0.0.1:8080

# View reports
vulnscan report --list
vulnscan report --last
```

---

## Options

```
vulnscan scan [OPTIONS] TARGET...

  -f, --file PATH            File with target URLs (one per line)
  -m, --modules TEXT         xss,sqli,ssrf,lfi,rce,csrf,cors,open_redirect  [default: all]
  -d, --depth INT            Crawl depth  [default: 3]
  -u, --max-urls INT         Max URLs per target  [default: 50]
  -T, --threads INT          Concurrent tasks  [default: 5]
  -t, --timeout INT          HTTP timeout (s)  [default: 30]
  --proxy TEXT               HTTP proxy URL
  --no-ml                    Disable ML detection
  -o, --output PATH          Output file (auto-named if omitted)
  --format [html|json|txt]   Report format  [default: html]
  --telegram                 Send final report via Telegram
  --notify-each              Telegram alert per finding (real-time)
  -v, --verbose              Verbose output
```

---

## Configuration

```bash
# Set once — stored in ~/.vulnscan.conf
vulnscan config --set TELEGRAM_TOKEN=your_bot_token
vulnscan config --set TELEGRAM_CHAT_ID=your_chat_id

# Or use env vars
export TELEGRAM_TOKEN=xxx
export TELEGRAM_CHAT_ID=xxx

vulnscan config        # show current config
```

---

## Web dashboard (optional)

```bash
vulnscan web                          # http://127.0.0.1:5001
vulnscan web --host 0.0.0.0 --port 8080
```

---

## ML models

Pre-trained sklearn models live in `models/`. Retrain:

```bash
python generate_training_data.py
python train_ml_models.py
```

---

## Structure

```
security-scanner/
├── scanner/            # CLI package
│   ├── cli.py          # Click entry point
│   ├── config.py       # Env-based config
│   ├── core/orchestrator.py
│   ├── scanners/       # xss, sqli, ssrf, lfi, rce, csrf, cors, open_redirect
│   ├── ml/detector.py
│   └── utils/          # http, output (Rich), report, notify (Telegram)
├── app/                # Legacy Flask web UI
├── models/             # Trained ML models (.pkl)
├── exploits/           # Exploit templates
└── setup.py
```

---

## License

MIT — authorized security testing only.

---

<!-- legacy badges below -->

[![Python Badge](https://img.shields.io/badge/Python-3.8%2B-3776ab?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Security Status](https://img.shields.io/badge/Security-Advanced-brightgreen?style=flat-square)](https://github.com/oliviaisntcringe/security-scanner)
[![ML Implementation](https://img.shields.io/badge/ML-Implemented-blue?style=flat-square&logo=tensorflow&logoColor=white)](https://github.com/oliviaisntcringe/security-scanner)
[![Code Status](https://img.shields.io/badge/Status-Beta-orange?style=flat-square)](https://github.com/oliviaisntcringe/security-scanner)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Completion](https://img.shields.io/badge/Completion-85%25-blue?style=flat-square)](#project-status-metrics)

A sophisticated security scanning tool combining traditional vulnerability detection with machine learning.

</div>

A sophisticated security scanning tool that combines traditional vulnerability detection techniques with machine learning to identify potential security issues in web applications.

## 🔍 Features

### Completed Features
- ✅ Advanced vulnerability scanning for common security issues:
  - Cross-Site Scripting (XSS)
  - SQL Injection (SQLi)
  - Cross-Site Request Forgery (CSRF)
  - Server-Side Request Forgery (SSRF)
  - Local File Inclusion (LFI)
  - Remote Code Execution (RCE)
- ✅ Machine learning-based vulnerability detection
- ✅ Smart fuzzing capabilities
- ✅ Web crawling and mapping functionality
- ✅ Report generation with detailed findings
- ✅ Telegram integration for real-time notifications
- ✅ Exploit generation for confirmed vulnerabilities
- ✅ Training data generation for ML models
- ✅ Configurable scanning parameters

### Project Status Metrics
| Component | Completion | Notes |
|-----------|------------|-------|
| Core Scanning Engine | 90% | Base functionality complete, some optimizations needed |
| ML Implementation | 85% | Models trained, feature extraction working |
| User Interface | 60% | Basic web UI implemented, needs enhancement |
| Reporting | 75% | HTML and notification systems working |
| Documentation | 40% | In-code documentation present, user docs needed |

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- Required packages listed in `requirements.txt`

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure Telegram notifications (optional):
```bash
# Edit telegram_setup.sh with your bot token and chat ID
./telegram_setup.sh
```

### Usage

#### Basic Usage
Run the scanner with default settings:
```bash
python run.py
```

#### Advanced Usage
Run with specific filtering options:
```bash
./run_with_filters.sh
```

#### Training ML Models
Generate training data and train ML models:
```bash
python generate_training_data.py
python train_ml_models.py
```

## 📊 Project Structure

```
security-scanner/
├── app/                     # Core application code
│   ├── scanners/            # Vulnerability scanners
│   ├── utils/               # Utility functions
│   ├── models/              # ML model definitions
│   ├── templates/           # Report templates
│   └── config.py            # Configuration parameters
├── models/                  # Trained ML models
├── exploits/                # Generated exploit code
├── reports/                 # Scan reports
├── results/                 # Scan results
├── training_data/           # ML training datasets
└── logs/                    # Application logs
```

## ��� Future Enhancements

### High Priority
- [ ] Implement more advanced ML feature extraction
- [ ] Add support for authenticated scanning
- [ ] Enhance exploit generation capabilities
- [ ] Improve performance with parallel scanning

### Medium Priority
- [ ] Develop a more user-friendly web interface
- [ ] Add support for custom payload definitions
- [ ] Implement a REST API for integration with other tools
- [ ] Create comprehensive documentation

### Low Priority
- [ ] Add container-based deployment options
- [ ] Implement cloud storage for scan results
- [ ] Create visualization dashboards for trends
- [ ] Add support for scheduled scans

## 🧠 Machine Learning Capabilities

The project employs several ML models to detect vulnerabilities that traditional pattern-matching might miss:

| Vulnerability | Detection Accuracy | Min Features |
|---------------|-------------------|-------------|
| XSS           | 85%               | 35          |
| SQLi          | 82%               | 35          |
| CSRF          | 78%               | 35          |
| SSRF          | 75%               | 35          |
| LFI           | 80%               | 35          |
| RCE           | 77%               | 35          |

## 📝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security Considerations

This tool is designed for security professionals to test their own systems or systems they have permission to test. Unauthorized scanning of systems is illegal and unethical.

## 📊 Project Roadmap

| Quarter | Planned Features |
|---------|------------------|
| Q3 2023 | Enhanced ML models, API development |
| Q4 2023 | UI improvements, Docker integration |
| Q1 2024 | Cloud integration, Scheduled scanning |
| Q2 2024 | Enterprise features, Access control |
