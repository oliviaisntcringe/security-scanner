#!/usr/bin/env python3
import os
import sys
import requests
import json

# Get Telegram credentials from environment or use default
TELEGRAM_TOKEN = os.environ.get('TELEGRAM_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

print(f"Testing Telegram connectivity with:")
print(f"Token: {'[SET]' if TELEGRAM_TOKEN else '[NOT SET]'}")
print(f"Chat ID: {'[SET]' if TELEGRAM_CHAT_ID else '[NOT SET]'}")

if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
    print("Error: TELEGRAM_TOKEN and/or TELEGRAM_CHAT_ID not set.")
    print("Please run: source telegram_setup.sh")
    sys.exit(1)

# Test sending a message
message = "Test message from security scanner"
url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
data = {
    'chat_id': TELEGRAM_CHAT_ID,
    'text': message
}

print("\nAttempting to send test message...")
try:
    # Without SSL verification to match aiohttp configuration
    response = requests.post(url, json=data, verify=False)
    print(f"Response status code: {response.status_code}")
    print(f"Response body: {response.text}")
    
    if response.status_code == 200:
        print("\nSuccess! Test message sent to Telegram.")
    else:
        print("\nError: Failed to send message to Telegram.")
        # Check for common issues
        response_data = response.json()
        if 'description' in response_data:
            error_desc = response_data['description']
            if 'bot was blocked' in error_desc.lower():
                print("The bot was blocked by the user. Please unblock the bot in Telegram.")
            elif 'chat not found' in error_desc.lower():
                print("Chat ID not found. Make sure your Chat ID is correct.")
            elif 'unauthorized' in error_desc.lower():
                print("Unauthorized. Your bot token is invalid.")
            else:
                print(f"Telegram API error: {error_desc}")
except Exception as e:
    print(f"Error: {e}")

print("\nAdditional diagnostics:")
print(f"1. Your bot token format looks {'valid' if ':' in TELEGRAM_TOKEN else 'INVALID'}")
print(f"2. Chat ID format looks {'valid' if TELEGRAM_CHAT_ID.isdigit() else 'INVALID'}")
print(f"3. Are you on a network that might block Telegram API? Try with a VPN if needed.")
print("\nReminder: To get a valid Bot token, message @BotFather on Telegram.")
print("To get your Chat ID, message @userinfobot on Telegram.")
print("Update telegram_setup.sh with these values, then run: source telegram_setup.sh") 