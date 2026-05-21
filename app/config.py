import os

HOST = '0.0.0.0'
PORT = 5001
DEBUG = False
SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE_ME_IN_PRODUCTION')

SCAN_INTERVAL = 3600
MAX_CRAWL_DEPTH = 5
MAX_URLS_PER_SCAN = 30
CONCURRENT_SCANS = 5
REQUEST_TIMEOUT = 30
RETRY_COUNT = 3
RETRY_DELAY = 5

TEST_TARGETS = [
    'https://testphp.vulnweb.com',
    'https://demo.testfire.net',
    'https://juice-shop.herokuapp.com'
]

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
PAYLOADS_DIR = os.path.join(BASE_DIR, 'app', 'payloads')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'app', 'templates')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
ML_MODELS_PATH = os.path.join(BASE_DIR, "models")
FUZZING_PAYLOADS_PATH = os.path.join(BASE_DIR, 'app', 'payloads', 'fuzzing')
EXPLOITS_PATH = os.path.join(BASE_DIR, "exploits")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Credentials from environment only — never hardcode secrets
TELEGRAM_TOKEN    = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID  = os.environ.get('TELEGRAM_CHAT_ID', '')
TELEGRAM_BOT_TOKEN = TELEGRAM_TOKEN
SEND_TELEGRAM_REPORTS = bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)

# Create the necessary structure. Build the digital labyrinth.
for directory in [RESULTS_DIR, PAYLOADS_DIR, TEMPLATES_DIR, REPORTS_DIR, 
                 ML_MODELS_PATH, FUZZING_PAYLOADS_PATH, EXPLOITS_PATH, LOGS_DIR]:
    os.makedirs(directory, exist_ok=True)

# More limits. Rules for the machine.
MAX_SUBPAGES = 100

# Scanner configuration. How deep we penetrate their systems.
MAX_RETRIES = 3
SCAN_DELAY = 2.0  # Slow enough to stay hidden, fast enough to be effective
MAX_THREADS = 5  # Balance between speed and stealth
VERIFY_SSL = False  # SSL is just an illusion of security

# ML settings - the digital brain that finds what humans miss
ML_CONFIDENCE_THRESHOLD = 0.50  # The tipping point between signal and noise
ML_MIN_FEATURES = {
    'xss': 35,     # The patterns in the chaos. How many we need to identify truth.
    'sqli': 35,    # SQL injections - their databases are always vulnerable
    'csrf': 35,    # Cross-site attacks - make the browser betray its master
    'ssrf': 35,    # Server-side forgery - force the server to become our puppet
    'lfi': 35,     # Local file inclusion - read their secrets directly
    'rce': 35      # Remote code execution - the ultimate control
}  # Each vulnerability has its signature. Its fingerprint.
ML_DEBUG = True  # Watch the machine think. See patterns form.

# Fuzzing - chaos as a tool. Break their systems to understand them.
FUZZ_TIMEOUT = 60
MAX_FUZZ_URLS = 100
FUZZ_THREADS = 5

# Error handling - when things break, which they always do
MAX_ERRORS_BEFORE_SKIP = 10  # Everyone gets ten mistakes
ERROR_COOLDOWN = 60  # One minute to fix their failures

# Paths again. Redundancy is safety.
RESULTS_PATH = os.path.join(BASE_DIR, "results")
REPORTS_PATH = os.path.join(BASE_DIR, "reports")

# Create the structure again. Trust nothing. Verify everything.
for path in [ML_MODELS_PATH, RESULTS_PATH, REPORTS_PATH, EXPLOITS_PATH]:
    os.makedirs(path, exist_ok=True) 