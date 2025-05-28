#!/usr/bin/env python3
import os
import sys
import asyncio
import threading
import signal
import multiprocessing
import re
import argparse
from app import create_app, socketio
from app.scanners.advanced_scanner import AdvancedScanner
from app.config import HOST, PORT
from app.utils.helpers import LOG, set_log_level, toggle_command_filtering, add_filter_pattern

# Parse command-line arguments for output filtering
parser = argparse.ArgumentParser(description='Security Scanner with output filtering')
parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], 
                    default='INFO', help='Set the log level for filtering output')
parser.add_argument('--filter-commands', action='store_true', default=True,
                    help='Enable command output filtering (default: True)')
parser.add_argument('--no-filter', action='store_true', 
                    help='Disable all output filtering')
parser.add_argument('--filter-pattern', action='append',
                    help='Add custom patterns to filter from logs (can be used multiple times)')
args = parser.parse_args()

# Apply command line arguments to logging settings
if args.no_filter:
    set_log_level('DEBUG')
    toggle_command_filtering(False)
    LOG("[*] All output filtering disabled - showing everything")
else:
    set_log_level(args.log_level)
    toggle_command_filtering(args.filter_commands)
    if args.filter_pattern:
        for pattern in args.filter_pattern:
            add_filter_pattern(pattern)

# Create Flask app and scanner
app = create_app()
scanner = AdvancedScanner()
scan_thread = None
cleanup_done = False
cleanup_lock = threading.Lock()

def signal_handler(signum, frame):
    """Handle interrupt signals"""
    global cleanup_done
    
    print("\n[!] Shutdown signal received. Cleaning up...")
    
    with cleanup_lock:
        if not cleanup_done:
            cleanup()
            cleanup_done = True
    
    # If we get interrupted again, exit immediately
    if signum == signal.SIGINT:
        signal.signal(signal.SIGINT, signal.default_int_handler)
        sys.exit(1)

def cleanup():
    """Cleanup function to handle proper shutdown"""
    global scan_thread
    try:
        # Stop the scanner
        if scanner:
            scanner.running = False
            scanner.cleanup()
        
        # Wait for scan thread to finish
        if scan_thread and scan_thread.is_alive():
            scan_thread.join(timeout=5)
        
        # Ensure all detected vulnerabilities are saved to the consolidated file
        import os
        import json
        from app.config import RESULTS_DIR
        
        # Create consolidated file for any detected vulnerabilities in memory
        consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
        if hasattr(scanner, 'vulnerability_database') and scanner.vulnerability_database:
            all_vulns = {'vulnerabilities': []}
            
            # Load existing consolidated file if it exists
            if os.path.exists(consolidated_file):
                try:
                    with open(consolidated_file, 'r') as f:
                        all_vulns = json.load(f)
                        if not isinstance(all_vulns, dict) or 'vulnerabilities' not in all_vulns:
                            all_vulns = {'vulnerabilities': []}
                except Exception:
                    all_vulns = {'vulnerabilities': []}
                
            # Add in-memory vulnerabilities to consolidated file
            added_count = 0
            for url, data in scanner.vulnerability_database.items():
                if 'results' in data and 'vulnerabilities' in data['results']:
                    for vuln in data['results']['vulnerabilities']:
                        all_vulns['vulnerabilities'].append(vuln)
                        added_count += 1
            
            # Only write if we added any vulnerabilities
            if added_count > 0:
                print(f"[*] Added {added_count} vulnerabilities to consolidated file")
                with open(consolidated_file, 'w') as f:
                    json.dump(all_vulns, f, indent=2)
        
        # Generate and send HTML report to Telegram
        try:
            from app.utils.report_generator import ReportGenerator
            from app.config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID
            
            # Verify Telegram credentials before attempting to send
            if TELEGRAM_TOKEN and TELEGRAM_CHAT_ID:
                print(f"[*] Generating final HTML report with Telegram notifications")
                print(f"[*] Using Telegram token: ...{TELEGRAM_TOKEN[-5:]} and chat ID: {TELEGRAM_CHAT_ID}")
                asyncio.run(ReportGenerator.generate_html_report(send_telegram=True))
                print("[*] Final report generated with all detected vulnerabilities")
            else:
                print("[*] Generating final HTML report (no Telegram - credentials not found)")
                asyncio.run(ReportGenerator.generate_html_report(send_telegram=False))
        except ImportError as e:
            print(f"[!] Error importing modules for report generation: {e}")
        except Exception as e:
            print(f"[!] Error generating/sending report: {e}")
            import traceback
            print(f"[!] Error details: {traceback.format_exc()}")
            
        # Stop the socket server
        try:
            # Check if socketio is running in a proper request context
            from flask import has_app_context
            if has_app_context() and hasattr(socketio, 'server') and socketio.server is not None:
                socketio.stop()
            else:
                print("[*] SocketIO not initialized in this context, skipping stop")
        except Exception as e:
            print(f"[!] Error stopping socketio: {e}")
            
        print("[*] Cleanup completed")
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")
        import traceback
        print(f"[!] Error details: {traceback.format_exc()}")

def update_telegram_config():
    """Update Telegram config in config.py based on telegram_setup.sh"""
    # Path to telegram_setup.sh and config.py
    telegram_setup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'telegram_setup.sh')
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'config.py')

    if not os.path.exists(telegram_setup_path):
        print(f"[*] Telegram setup file not found: {telegram_setup_path}")
        return False

    if not os.path.exists(config_path):
        print(f"[*] Config file not found: {config_path}")
        return False

    print(f"[*] Loading Telegram credentials from {telegram_setup_path}")
    
    # Extract token and chat ID from telegram_setup.sh
    token = None
    chat_id = None

    with open(telegram_setup_path, 'r') as f:
        content = f.read()
        # Print the content for debugging
        print(f"[DEBUG] File content:\n{content[:100]}...")  # Just print first 100 chars
        
        # Extract token with more robust regex
        token_match = re.search(r'export\s+TELEGRAM_TOKEN=["\']([^"\']+)["\']', content)
        if token_match:
            token = token_match.group(1)
            print(f"[*] Found token: {token[:5]}...")
        
        # Extract chat ID with more robust regex
        chat_id_match = re.search(r'export\s+TELEGRAM_CHAT_ID=["\']([^"\']+)["\']', content)
        if chat_id_match:
            chat_id = chat_id_match.group(1)
            print(f"[*] Found chat ID: {chat_id}")

    if not token or not chat_id:
        print(f"[!] Telegram credentials incomplete - Token found: {'Yes' if token else 'No'}, Chat ID found: {'Yes' if chat_id else 'No'}")
        return False
        
    # Set environment variables as well for any code that uses them directly
    os.environ['TELEGRAM_TOKEN'] = token
    os.environ['TELEGRAM_BOT_TOKEN'] = token
    os.environ['TELEGRAM_CHAT_ID'] = chat_id

    # Read config.py
    with open(config_path, 'r') as f:
        config_content = f.read()

    # Prepare replacement patterns
    token_pattern = r'TELEGRAM_TOKEN = .*'  # More broad pattern to match any definition
    token_replacement = f'TELEGRAM_TOKEN = "{token}"  # Set directly from telegram_setup.sh'

    chat_id_pattern = r'TELEGRAM_CHAT_ID = .*'  # More broad pattern
    chat_id_replacement = f'TELEGRAM_CHAT_ID = "{chat_id}"  # Set directly from telegram_setup.sh'

    bot_token_pattern = r'TELEGRAM_BOT_TOKEN = .*'
    bot_token_replacement = f'TELEGRAM_BOT_TOKEN = "{token}"  # Set directly from telegram_setup.sh'

    # Apply replacements and count how many were made
    new_config, token_count = re.subn(token_pattern, token_replacement, config_content)
    new_config, chat_id_count = re.subn(chat_id_pattern, chat_id_replacement, new_config)
    new_config, bot_token_count = re.subn(bot_token_pattern, bot_token_replacement, new_config)
    
    print(f"[*] Replaced {token_count} token references, {chat_id_count} chat ID references, and {bot_token_count} bot token references")

    # Write updated config.py
    with open(config_path, 'w') as f:
        f.write(new_config)

    print("[✓] Telegram credentials successfully configured")
    
    # Also directly set in app.config for the current run
    from app import config
    config.TELEGRAM_TOKEN = token
    config.TELEGRAM_BOT_TOKEN = token
    config.TELEGRAM_CHAT_ID = chat_id
    config.SEND_TELEGRAM_REPORTS = True
    
    print(f"[*] Verified configuration: Token={token[:5]}..., Chat ID={chat_id}, Send Reports=True")
    return True

if __name__ == '__main__':
    try:
        # Ensure we're in the correct directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        
        # Update Telegram configuration if telegram_setup.sh exists
        update_telegram_config()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start continuous scanning in background
        scan_thread = threading.Thread(
            target=asyncio.run,
            args=(scanner.continuous_scan(),),
            daemon=True
        )
        scan_thread.start()
        
        # Run the web application
        socketio.run(app, host=HOST, port=PORT, debug=True, use_reloader=False)
        
    except Exception as e:
        print(f"[!] Critical error: {e}")
        cleanup()
        sys.exit(1) 