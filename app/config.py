import os

# They're always listening. Hide in plain sight.
HOST = '0.0.0.0'
PORT = 5001  # Standard ports are monitored. Stay off their radar.
DEBUG = True
SECRET_KEY = os.environ.get('SECRET_KEY', 'CHANGE_ME_IN_PRODUCTION')

# Time is a construct. But servers need rhythm.
SCAN_INTERVAL = 3600  # One hour. Predictable, but necessary evil.
MAX_CRAWL_DEPTH = 5
MAX_URLS_PER_SCAN = 30
CONCURRENT_SCANS = 5  # Any more would draw attention
REQUEST_TIMEOUT = 30  # Patience is a virtue they don't possess
RETRY_COUNT = 3  # Three chances. That's all they get.
RETRY_DELAY = 5  # Make them wait. Control the tempo.

# Sacrificial lambs. Practice targets with known flaws.
TEST_TARGETS = [
    'https://testphp.vulnweb.com',
    'https://demo.testfire.net',
    'https://juice-shop.herokuapp.com'
]

# Digital breadcrumbs. Where we store the evidence of their failures.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(BASE_DIR, 'results')
PAYLOADS_DIR = os.path.join(BASE_DIR, 'app', 'payloads')
TEMPLATES_DIR = os.path.join(BASE_DIR, 'app', 'templates')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
ML_MODELS_PATH = os.path.join(BASE_DIR, "models")
FUZZING_PAYLOADS_PATH = os.path.join(BASE_DIR, 'app', 'payloads', 'fuzzing')
EXPLOITS_PATH = os.path.join(BASE_DIR, "exploits")
LOGS_DIR = os.path.join(BASE_DIR, "logs")  # Where we record their mistakes

# Telegram - communication over corporate channels. They don't monitor these... yet.
# Tokens are just digital keys. So easy to steal.
TELEGRAM_TOKEN = "7695047242:AAH_FLMzTJL7cM2_uJCM8nWOTjltfouNx5Q"  # Set directly from telegram_setup.sh
TELEGRAM_CHAT_ID = "7168936119"  # Set directly from telegram_setup.sh
# Redundancy. Always have a backup key.
TELEGRAM_BOT_TOKEN = "7695047242:AAH_FLMzTJL7cM2_uJCM8nWOTjltfouNx5Q"  # Set directly from telegram_setup.sh
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