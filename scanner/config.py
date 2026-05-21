"""
Configuration management — reads from env vars and ~/.vulnscan.conf
No hardcoded secrets.
"""
import os
import configparser
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent

# ── Directories ────────────────────────────────────────────────────────────────
RESULTS_DIR   = BASE_DIR / "results"
REPORTS_DIR   = BASE_DIR / "reports"
MODELS_DIR    = BASE_DIR / "models"
PAYLOADS_DIR  = BASE_DIR / "app" / "payloads" / "fuzzing"
EXPLOITS_DIR  = BASE_DIR / "exploits"
LOGS_DIR      = BASE_DIR / "logs"

for _d in [RESULTS_DIR, REPORTS_DIR, MODELS_DIR, PAYLOADS_DIR, EXPLOITS_DIR, LOGS_DIR]:
    _d.mkdir(parents=True, exist_ok=True)

# ── Config file (~/.vulnscan.conf) ─────────────────────────────────────────────
_conf = configparser.ConfigParser()
_conf_path = Path.home() / ".vulnscan.conf"
if _conf_path.exists():
    _conf.read(_conf_path)

def _get(key: str, section: str = "DEFAULT", fallback: str = "") -> str:
    """Env var takes priority, then config file, then fallback."""
    return os.environ.get(key) or _conf.get(section, key, fallback=fallback)

# ── Telegram ───────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN   = _get("TELEGRAM_TOKEN")
TELEGRAM_CHAT_ID = _get("TELEGRAM_CHAT_ID")

# ── Scanner defaults ───────────────────────────────────────────────────────────
REQUEST_TIMEOUT  = int(_get("REQUEST_TIMEOUT", fallback="30"))
MAX_CRAWL_DEPTH  = int(_get("MAX_CRAWL_DEPTH", fallback="3"))
MAX_URLS         = int(_get("MAX_URLS",         fallback="50"))
CONCURRENT_TASKS = int(_get("CONCURRENT_TASKS", fallback="5"))
SCAN_DELAY       = float(_get("SCAN_DELAY",     fallback="0.5"))
VERIFY_SSL       = _get("VERIFY_SSL", fallback="false").lower() == "true"

# ── ML ─────────────────────────────────────────────────────────────────────────
ML_CONFIDENCE_THRESHOLD = float(_get("ML_CONFIDENCE_THRESHOLD", fallback="0.50"))
