#!/usr/bin/env python3
import os
import sys
import asyncio
import threading
import signal
import multiprocessing
import logging
import traceback

# Set up verbose logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("debug.log"),
        logging.StreamHandler()
    ]
)

# Monkey patch the LOG function to include stack trace for errors
from app.utils.helpers import LOG as original_LOG

def enhanced_LOG(msg):
    original_LOG(msg)
    if msg.startswith("[!]"):  # Error message
        logging.error(f"ENHANCED ERROR LOG: {msg}")
        logging.error(f"Stack trace: {traceback.format_exc()}")

# Replace the LOG function
import app.utils.helpers
app.utils.helpers.LOG = enhanced_LOG

# Continue with normal imports
from app import create_app, socketio
from app.scanners.advanced_scanner import AdvancedScanner
from app.config import HOST, PORT

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
        # Generate and send HTML report to Telegram
        try:
            from app.utils.report_generator import ReportGenerator
            asyncio.run(ReportGenerator.generate_html_report(send_telegram=True))
        except Exception as e:
            print(f"[!] Error generating/sending report: {e}")
            logging.error(f"Report generation error: {e}")
            logging.error(f"Stack trace: {traceback.format_exc()}")
        # Stop the socket server
        try:
            socketio.stop()
        except Exception as e:
            print(f"[!] Error stopping socketio: {e}")
            logging.error(f"Socketio stop error: {e}")
            logging.error(f"Stack trace: {traceback.format_exc()}")
        print("[*] Cleanup completed")
    except Exception as e:
        print(f"[!] Error during cleanup: {e}")
        logging.error(f"Cleanup error: {e}")
        logging.error(f"Stack trace: {traceback.format_exc()}")

if __name__ == '__main__':
    try:
        # Ensure we're in the correct directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
        
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
        logging.critical(f"Critical startup error: {e}")
        logging.critical(f"Stack trace: {traceback.format_exc()}")
        cleanup()
        sys.exit(1) 