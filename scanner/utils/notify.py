"""
Telegram notification helpers.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, Any, Optional

import aiohttp

from scanner.config import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID


def _configured() -> bool:
    return bool(TELEGRAM_TOKEN and TELEGRAM_CHAT_ID)


async def send_message(text: str) -> bool:
    if not _configured():
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as r:
                return r.status == 200
    except Exception:
        return False


async def send_file(path: Path, caption: str = "") -> bool:
    if not _configured() or not path.exists():
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
    data = aiohttp.FormData()
    data.add_field("chat_id", TELEGRAM_CHAT_ID)
    if caption:
        data.add_field("caption", caption)
    data.add_field("document", path.read_bytes(), filename=path.name)
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(url, data=data, timeout=aiohttp.ClientTimeout(total=60)) as r:
                return r.status == 200
    except Exception:
        return False


async def notify_vuln(finding: Dict[str, Any]) -> None:
    if not _configured():
        return
    sev   = finding.get("severity", "medium").upper()
    icons = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}
    icon  = icons.get(sev, "⚪")
    msg = (
        f"{icon} <b>{sev} — {finding.get('type','?').upper()}</b>\n"
        f"URL: <code>{finding.get('url','N/A')}</code>\n"
        f"Param: <code>{finding.get('parameter','N/A')}</code>\n"
        f"Payload: <code>{str(finding.get('payload','N/A'))[:200]}</code>"
    )
    await send_message(msg)


async def notify_report(report_path: Path, summary: str) -> None:
    if not _configured():
        return
    await send_message(f"📋 <b>Scan complete</b>\n{summary}")
    await send_file(report_path, caption="Full scan report")
