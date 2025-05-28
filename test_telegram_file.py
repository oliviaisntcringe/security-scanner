#!/usr/bin/env python3
import os
import sys
import requests
import json
import time

# Get Telegram credentials from environment or use default
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

print(f"Testing Telegram file upload with:")
print(f"Token: {'[SET]' if TELEGRAM_TOKEN else '[NOT SET]'}")
print(f"Chat ID: {'[SET]' if TELEGRAM_CHAT_ID else '[NOT SET]'}")

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("Error: TELEGRAM_TOKEN and/or TELEGRAM_CHAT_ID not set.")
    print("Please run: source telegram_setup.sh")
    sys.exit(1)

# Create test file
test_file_path = f"test_report_{int(time.time())}.html"
with open(test_file_path, "w") as f:
    f.write("""
    <html>
    <head><title>Security Scanner Test Report</title></head>
    <body>
        <h1>Test Security Report</h1>
        <p>This is a test report to verify file upload functionality.</p>
    </body>
    </html>
    """)

print(f"\nCreated test file: {test_file_path}")

# Test sending a file
url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"

print("\nAttempting to send test file...")
try:
    # Using requests for simplicity
    with open(test_file_path, 'rb') as f:
        files = {'document': f}
        data = {'chat_id': TELEGRAM_CHAT_ID}
        response = requests.post(url, data=data, files=files, verify=False)
    
    print(f"Response status code: {response.status_code}")
    print(f"Response body: {response.text}")
    
    if response.status_code == 200:
        print("\nSuccess! Test file sent to Telegram.")
    else:
        print("\nError: Failed to send file to Telegram.")
        response_data = response.json()
        if 'description' in response_data:
            error_desc = response_data['description']
            print(f"Telegram API error: {error_desc}")
except Exception as e:
    print(f"Error: {e}")
finally:
    # Cleanup
    if os.path.exists(test_file_path):
        os.remove(test_file_path)
        print(f"\nCleaned up test file: {test_file_path}")

print("\nTest completed.") 