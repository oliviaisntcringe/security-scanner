"""
Open Redirect scanner.
"""
from __future__ import annotations

import time
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/%2F..",
    "https:evil.com",
    "\\\\evil.com",
    "//google.com%2F@evil.com",
    "/%09/evil.com",
    "/%2F/evil.com",
    "//%5Cevil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
]

REDIRECT_PARAMS = {"redirect", "url", "next", "return", "target", "rurl",
                   "dest", "destination", "redir", "redirect_uri", "redirect_url",
                   "return_to", "return_url", "path", "image_url", "go", "goto",
                   "link", "data", "to", "out", "view", "open", "callback"}


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url)

    if not parsed.query:
        return findings

    params = parse_qs(parsed.query, keep_blank_values=True)
    candidate_params = [p for p in params if p.lower() in REDIRECT_PARAMS]

    for param in candidate_params:
        for payload in PAYLOADS:
            tp = {k: v[0] for k, v in params.items()}
            tp[param] = payload
            test_url = parsed._replace(query=urlencode(tp)).geturl()
            resp = await http_util.get(session, test_url, allow_redirects=False, timeout=10)
            if resp is None:
                continue
            if resp.status in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "evil.com" in location or "javascript:" in location or "data:" in location:
                    findings.append(_make(url, param, payload, location))
                    break

    return findings


def _make(url, param, payload, location) -> Dict[str, Any]:
    return {
        "type":      "open_redirect",
        "severity":  "medium",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   "redirect",
        "evidence":  f"Redirected to: {location}",
        "details":   "Open Redirect",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
