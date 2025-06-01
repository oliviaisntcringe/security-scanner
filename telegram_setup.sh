#!/bin/bash

# Instructions:
# 1. Edit this file to add your Telegram bot token and chat ID
# 2. Run this script with: source telegram_setup.sh
# 3. Then run the security scanner

# Your Telegram Bot Token - Replace with your actual bot token
# You can get this from @BotFather on Telegram
export TELEGRAM_TOKEN=""

# Your Telegram Chat ID - Replace with your actual chat ID
# You can get this by messaging @userinfobot on Telegram
export TELEGRAM_CHAT_ID=""

# Display configuration
echo "Telegram configuration set:"
echo "TELEGRAM_TOKEN: ${TELEGRAM_TOKEN:0:5}... (hidden for security)"
echo "TELEGRAM_CHAT_ID: ${TELEGRAM_CHAT_ID}"

echo ""
echo "To test your configuration, run:"
echo "curl -s \"https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage?chat_id=${TELEGRAM_CHAT_ID}&text=Test\" | grep \"ok\":true" 