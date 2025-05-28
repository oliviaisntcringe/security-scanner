import os
import ssl
import json
import time
import aiohttp
import certifi
import html
from datetime import datetime
from ..config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, RESULTS_DIR, SEND_TELEGRAM_REPORTS
import builtins
import logging
import re
from typing import Set, Dict, Any, List, Optional

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='debug.log',
    filemode='a'
)

# Global variable to control log filtering
LOG_LEVEL = "INFO"  # Can be "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"
FILTER_COMMANDS = True  # Whether to filter command output
COMMAND_FILTER_PATTERNS = [
    r'\[ML\]',         # Filter ML model messages
    r'Target acquisition',  # Filter target acquisition messages
    r'Executing neural network',  # Filter neural network messages
    r'Bypass high-security',  # Filter domain bypass messages
    r'Neural pattern input insufficient',  # Filter neural pattern padding messages
    r'padding with zeros',  # Filter zero padding messages
]

def set_log_level(level: str) -> None:
    """Set the global log level for filtering"""
    global LOG_LEVEL
    if level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        LOG_LEVEL = level
        LOG(f"[*] Log level set to {LOG_LEVEL}")

def toggle_command_filtering(enable: bool) -> None:
    """Enable or disable command output filtering"""
    global FILTER_COMMANDS
    FILTER_COMMANDS = enable
    LOG(f"[*] Command filtering {'enabled' if enable else 'disabled'}")

def add_filter_pattern(pattern: str) -> None:
    """Add a new pattern to filter from logs"""
    global COMMAND_FILTER_PATTERNS
    COMMAND_FILTER_PATTERNS.append(pattern)
    LOG(f"[*] Added new filter pattern: {pattern}")

def should_filter_log(message: str) -> bool:
    """Determine if a message should be filtered based on patterns"""
    if not FILTER_COMMANDS:
        return False
        
    for pattern in COMMAND_FILTER_PATTERNS:
        if re.search(pattern, message):
            return True
    return False

def LOG(message: str, level: str = "INFO") -> None:
    """Enhanced logging function with filtering capability"""
    # Skip logging if the message should be filtered
    if should_filter_log(message):
        return
        
    # Skip logging if the level is below the current LOG_LEVEL
    level_priority = {"DEBUG": 1, "INFO": 2, "WARNING": 3, "ERROR": 4, "CRITICAL": 5}
    if level_priority.get(level, 2) < level_priority.get(LOG_LEVEL, 2):
        return
    
    try:
        # Log to console
        print(message)
        
        # Log to file with appropriate level
        if level == "DEBUG":
            logging.debug(message)
        elif level == "INFO":
            logging.info(message)
        elif level == "WARNING":
            logging.warning(message)
        elif level == "ERROR":
            logging.error(f"ENHANCED ERROR LOG: {message}")
        elif level == "CRITICAL":
            logging.critical(f"CRITICAL ERROR: {message}")
            
    except Exception as e:
        # Fallback to basic print if logging fails
        print(f"[!] Logging error: {e}")
        print(message)

async def send_telegram_alert(msg):
    """Send alert to Telegram"""
    if not msg or not SEND_TELEGRAM_REPORTS:
        return
    
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': msg,
        'parse_mode': 'HTML'
    }
    
    try:
        ssl_ctx = ssl._create_unverified_context()
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as s:
            await s.post(url, data=data)
    except Exception as e:
        LOG(f"[!] Telegram error: {e}")

async def send_telegram_file(file_path, caption=None):
    """Send file to Telegram with file size check and improved error surfacing"""
    if not SEND_TELEGRAM_REPORTS:
        return
        
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
    try:
        if os.path.getsize(file_path) > 49 * 1024 * 1024:
            LOG(f"[!] Report file too large to send to Telegram.")
            try:
                from flask_socketio import emit
                emit('log', '[!] Report file too large to send to Telegram.')
            except:
                pass
            return
        ssl_ctx = ssl._create_unverified_context()
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            with open(file_path, 'rb') as f:
                data = aiohttp.FormData()
                data.add_field('chat_id', TELEGRAM_CHAT_ID)
                data.add_field('document', f, filename=os.path.basename(file_path))
                if caption:
                    data.add_field('caption', caption)
                async with session.post(url, data=data) as response:
                    if response.status != 200:
                        error_msg = f"[!] Failed to send file to Telegram: {await response.text()}"
                        LOG(error_msg)
                        try:
                            from flask_socketio import emit
                            emit('log', error_msg)
                        except:
                            pass
                    else:
                        LOG("[*] Report file sent to Telegram successfully")
                        try:
                            from flask_socketio import emit
                            emit('log', '[*] Report file sent to Telegram successfully')
                        except:
                            pass
    except Exception as e:
        error_msg = f"[!] Error sending file to Telegram: {e}"
        LOG(error_msg)
        try:
            from flask_socketio import emit
            emit('log', error_msg)
        except:
            pass

def save_to_txt(vuln_type, url, content):
    """Save vulnerability findings to text file"""
    ts = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    os.makedirs(RESULTS_DIR, exist_ok=True)
    path = os.path.join(RESULTS_DIR, f"{ts}_{vuln_type}.txt")
    
    with open(path, 'w') as f:
        f.write(f"Vulnerability: {vuln_type}\nURL: {url}\nTime: {ts}\n\n{content}")
    LOG(f"[*] Saved to {path}")

def save_to_html(vuln_type, url, content):
    """Save vulnerability findings to HTML report"""
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_file = os.path.join(RESULTS_DIR, f"{vuln_type}_report.html")
    
    # Parse the content into a structured format
    if isinstance(content, dict):
        details = content
    else:
        # Try to parse content string into structured format
        details = {}
        for line in content.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                details[key.strip()] = value.strip()
            else:
                details['Details'] = details.get('Details', '') + line + '\n'
    
    # Create HTML content with proper formatting
    html_content = f"""
    <div class="vuln-entry">
        <h3>Vulnerability Found: {html.escape(vuln_type.upper())}</h3>
        <p><strong>URL:</strong> <a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></p>
        <p><strong>Time:</strong> {html.escape(ts)}</p>
        <div class="details">
    """
    
    # Add structured details
    for key, value in details.items():
        if key.lower() == 'payload':
            html_content += f"""
            <div class="payload-section">
                <p><strong>{html.escape(key)}:</strong></p>
                <pre class="payload"><code>{html.escape(str(value))}</code></pre>
            </div>
            """
        else:
            html_content += f"""
            <p><strong>{html.escape(key)}:</strong> {html.escape(str(value))}</p>
            """
    
    html_content += """
        </div>
    </div>
    """
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(report_file), exist_ok=True)
    
    # Write the content
    with open(report_file, 'a') as f:
        f.write(html_content)
    LOG(f"[*] Added to HTML report: {report_file}")

def load_history() -> Set[str]:
    """Load scan history from file"""
    history_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'history.json')
    try:
        with open(history_path, 'r') as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    except Exception as e:
        LOG(f"[!] Error loading history: {e}", "ERROR")
        return set()

def save_history(history: Set[str]) -> None:
    """Save scan history to file"""
    try:
        history_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data', 'history.json')
        os.makedirs(os.path.dirname(history_path), exist_ok=True)
        with open(history_path, 'w') as f:
            json.dump(list(history), f)
    except Exception as e:
        LOG(f"[!] Error saving history: {e}", "ERROR")
        import traceback
        LOG(traceback.format_exc(), "ERROR")


def save_ml_detection(vuln_type, url, confidence, details="ML model detection"):
    """Save ML detection to consolidated vulnerabilities file"""
    import json
    import time
    import os
    
    # Create detailed evidence based on vulnerability type
    evidence = "The ML model detected patterns consistent with this vulnerability type based on: "
    
    if vuln_type == 'xss':
        evidence += "JavaScript event handlers, DOM manipulation methods, or user input reflection patterns."
        example_payload = "<script>alert('XSS')</script>"
    elif vuln_type == 'sqli':
        evidence += "Database query patterns, SQL-like syntax in parameters, or error-based SQL signatures."
        example_payload = "' OR 1=1; --"
    elif vuln_type == 'csrf':
        evidence += "Missing CSRF tokens, form submission patterns without proper protection."
        example_payload = "Cross-site form submission"
    elif vuln_type == 'ssrf':
        evidence += "URL parameters that could be manipulated for server-side requests."
        example_payload = "http://internal-server/admin"
    elif vuln_type == 'lfi':
        evidence += "Path traversal opportunities, file inclusion patterns."
        example_payload = "../../../etc/passwd"
    elif vuln_type == 'rce':
        evidence += "Command execution patterns, dangerous function usage."
        example_payload = "; cat /etc/passwd"
    else:
        evidence += "Structural patterns and code signatures associated with security weaknesses."
        example_payload = "Generic attack vector"
    
    # Create result structure
    result = {
        'type': vuln_type,
        'url': url,
        'confidence': confidence,
        'predicted': True,
        'details': details,
        'parameter': 'Multiple potential parameters detected',
        'payload': f"Example: {example_payload} (Not actually used - ML detection is non-intrusive)",
        'evidence': evidence,
        'detected_by': 'machine_learning',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Ensure results directory exists
    os.makedirs(RESULTS_DIR, exist_ok=True)
    
    # Path to consolidated file
    consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
    
    # Initialize or load existing vulnerabilities
    all_vulns = {'vulnerabilities': []}
    if os.path.exists(consolidated_file):
        try:
            with open(consolidated_file, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict) and 'vulnerabilities' in data:
                    all_vulns = data
        except Exception as e:
            LOG(f"[!] Error loading vulnerability database: {e}")
    
    # Add this vulnerability
    all_vulns['vulnerabilities'].append(result)
    
    # Update metadata
    all_vulns['metadata'] = {
        'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_vulnerabilities': len(all_vulns['vulnerabilities']),
        'last_scan_url': url,
        'last_scan_vulnerabilities': 1
    }
    
    # Save updated file
    try:
        with open(consolidated_file, 'w') as f:
            json.dump(all_vulns, f, indent=2)
        LOG(f"[*] Added {vuln_type} vulnerability for {url} to consolidated database")
        return True
    except Exception as e:
        LOG(f"[!] Error saving to vulnerability database: {e}")
        return False 