#!/usr/bin/env python3
import os
import re
import sys

print("[*] Updating Telegram credentials in config.py...")

# Path to telegram_setup.sh and config.py
telegram_setup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'telegram_setup.sh')
config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app', 'config.py')

if not os.path.exists(telegram_setup_path):
    print(f"[!] Error: {telegram_setup_path} not found")
    sys.exit(1)

if not os.path.exists(config_path):
    print(f"[!] Error: {config_path} not found")
    sys.exit(1)

# Extract token and chat ID from telegram_setup.sh
token = None
chat_id = None

with open(telegram_setup_path, 'r') as f:
    for line in f:
        if line.strip().startswith('export TELEGRAM_TOKEN='):
            token_match = re.search(r'export TELEGRAM_TOKEN="([^"]+)"', line)
            if token_match:
                token = token_match.group(1)
        elif line.strip().startswith('export TELEGRAM_CHAT_ID='):
            chat_id_match = re.search(r'export TELEGRAM_CHAT_ID="([^"]+)"', line)
            if chat_id_match:
                chat_id = chat_id_match.group(1)

if not token or not chat_id:
    print("[!] Error: Could not extract token or chat ID from telegram_setup.sh")
    print(f"Token found: {'Yes' if token else 'No'}")
    print(f"Chat ID found: {'Yes' if chat_id else 'No'}")
    sys.exit(1)

print(f"[*] Found token: {token[:5]}... and chat ID: {chat_id}")

# Read config.py
with open(config_path, 'r') as f:
    config_content = f.read()

# Prepare replacement patterns
token_pattern = r'TELEGRAM_TOKEN = os\.environ\.get\(.*?\)'
token_replacement = f'TELEGRAM_TOKEN = "{token}"  # Set directly from telegram_setup.sh'

chat_id_pattern = r'TELEGRAM_CHAT_ID = os\.environ\.get\(.*?\)'
chat_id_replacement = f'TELEGRAM_CHAT_ID = "{chat_id}"  # Set directly from telegram_setup.sh'

bot_token_pattern = r'TELEGRAM_BOT_TOKEN = .*'
bot_token_replacement = f'TELEGRAM_BOT_TOKEN = "{token}"  # Set directly from telegram_setup.sh'

# Apply replacements
config_content = re.sub(token_pattern, token_replacement, config_content)
config_content = re.sub(chat_id_pattern, chat_id_replacement, config_content)
config_content = re.sub(bot_token_pattern, bot_token_replacement, config_content)

# Write updated config.py
with open(config_path, 'w') as f:
    f.write(config_content)

print("[✓] Telegram credentials successfully updated in config.py")
print("[*] You can now generate reports with Telegram notifications enabled")
print("[*] Test with: python3 -c 'from app.utils.report_generator import ReportGenerator; import asyncio; asyncio.run(ReportGenerator.generate_html_report(send_telegram=True))'") 