import os
import aiohttp
import asyncio
import traceback
from ..config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, RETRY_COUNT, RETRY_DELAY
from .helpers import LOG

async def send_telegram_message(message, parse_mode='HTML'):
    """Send a text message to Telegram channel"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        LOG("[!] Telegram credentials not configured")
        return False

    LOG(f"[*] Sending message to Telegram (length: {len(message)})")
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': parse_mode
    }

    for attempt in range(RETRY_COUNT):
        try:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.post(url, json=data, ssl=False, timeout=30) as response:
                        if response.status == 200:
                            LOG("[*] Message sent to Telegram successfully")
                            return True
                        else:
                            error_text = await response.text()
                            LOG(f"[!] Failed to send message to Telegram. Status: {response.status}, Error: {error_text}")
                except aiohttp.ClientError as e:
                    LOG(f"[!] Telegram API connection error (attempt {attempt + 1}/{RETRY_COUNT}): {e}")
                except asyncio.TimeoutError:
                    LOG(f"[!] Telegram API request timed out (attempt {attempt + 1}/{RETRY_COUNT})")
        except Exception as e:
            LOG(f"[!] Error sending message to Telegram (attempt {attempt + 1}/{RETRY_COUNT}): {e}")
            LOG(f"[!] Stack trace: {traceback.format_exc()}")
        
        # Wait before retry if not last attempt
        if attempt < RETRY_COUNT - 1:
            await asyncio.sleep(RETRY_DELAY)
            continue
            
    LOG("[!] All attempts to send Telegram message failed")
    return False

async def send_report_to_telegram(report_file):
    """Send report file to Telegram channel with retries"""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        LOG(f"[!] Telegram credentials not configured. Bot token: {'Set' if TELEGRAM_BOT_TOKEN else 'Not set'}, Chat ID: {'Set' if TELEGRAM_CHAT_ID else 'Not set'}")
        return False

    if not os.path.exists(report_file):
        LOG(f"[!] Report file not found: {report_file}")
        return False
        
    # Log file info for debugging
    file_size = os.path.getsize(report_file)
    LOG(f"[*] Sending report file: {report_file} (Size: {file_size} bytes)")

    # Extract summary data first before sending the file
    summary = None
    try:
        with open(report_file, 'r') as f:
            content = f.read()
            # Extract vulnerability counts
            critical = content.count('critical')
            high = content.count('high')
            medium = content.count('medium')
            low = content.count('low')
            
            summary = f"""
📊 Scan Report Summary:
------------------------
🔴 Critical: {critical}
🟠 High: {high}
🟡 Medium: {medium}
🟢 Low: {low}
------------------------
Total: {critical + high + medium + low}

See attached report for details.
"""
            LOG(f"[*] Generated summary with {critical} critical, {high} high, {medium} medium, and {low} low vulnerabilities")
    except Exception as e:
        LOG(f"[!] Error generating summary: {e}")
        # Continue even if summary generation fails

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    
    # First send a notification message
    notification_sent = await send_telegram_message("🔍 New Security Scan Report Available 🔍")
    if not notification_sent:
        LOG("[!] Warning: Couldn't send notification message, there may be issues with Telegram credentials")
    
    for attempt in range(RETRY_COUNT):
        try:
            async with aiohttp.ClientSession() as session:
                # Prepare the form data
                form_data = aiohttp.FormData()
                form_data.add_field('chat_id', TELEGRAM_CHAT_ID)
                
                # Open and add the file
                file_bytes = None
                try:
                    with open(report_file, 'rb') as f:
                        file_bytes = f.read()  # Read the file contents into memory
                    
                    # Add the bytes directly to the form data
                    form_data.add_field('document', 
                                      file_bytes,
                                      filename=os.path.basename(report_file))
                except Exception as file_error:
                    LOG(f"[!] Error reading report file: {file_error}")
                    return False
                
                # Send the request
                LOG(f"[*] Sending request to Telegram API with bot token ending in '...{TELEGRAM_BOT_TOKEN[-5:]}' and chat ID '{TELEGRAM_CHAT_ID}'")
                async with session.post(url, data=form_data, ssl=False) as response:
                    response_text = await response.text()
                    if response.status == 200:
                        LOG(f"[*] Report sent to Telegram successfully: {response_text}")
                        
                        # Send summary message if we have one
                        if summary:
                            await send_telegram_message(summary)
                        
                        return True
                    else:
                        LOG(f"[!] Failed to send report to Telegram. Status: {response.status}, Error: {response_text}")
        except Exception as e:
            LOG(f"[!] Error sending report to Telegram (attempt {attempt + 1}/{RETRY_COUNT}): {e}")
            LOG(f"[!] Stack trace: {traceback.format_exc()}")
            if attempt < RETRY_COUNT - 1:
                await asyncio.sleep(RETRY_DELAY)
                continue
            else:
                # On final attempt failure, try to send error message
                await send_telegram_message(f"⚠️ Error sending report: {str(e)}")
    return False

async def send_vulnerability_alert(vulnerability):
    """Send immediate alert for high-severity vulnerabilities"""
    if not vulnerability:
        return False
        
    severity = vulnerability.get('severity', 'medium')
    vuln_type = vulnerability.get('type', 'unknown')
    url = vulnerability.get('url', 'N/A')
    confidence = vulnerability.get('confidence', 0)
    
    # Emoji mapping
    severity_emoji = {
        'critical': '🔴',
        'high': '🟠',
        'medium': '🟡',
        'low': '🟢'
    }
    
    message = f"""
{severity_emoji.get(severity, '⚪')} New {severity.upper()} Severity Vulnerability Detected!
------------------------------------------
Type: {vuln_type}
URL: {url}
Confidence: {confidence:.2f}
------------------------------------------
"""
    
    return await send_telegram_message(message) 