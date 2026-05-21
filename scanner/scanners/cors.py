"""
CORS misconfiguration scanner.
"""
from __future__ import annotations

import time
from typing import List, Dict, Any

import aiohttp

from scanner.utils import http as http_util

EVIL_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.com",
    "http://localhost",
    "http://127.0.0.1",
]


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for origin in EVIL_ORIGINS:
        resp = await http_util.get(session, url, headers={"Origin": origin}, timeout=10)
        if resp is None:
            continue

        acao = resp.headers.get("Access-Control-Allow-Origin", "")
        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

        if not acao:
            continue

        if acao == "*" and acac == "true":
            findings.append(_make(url, origin, acao, acac,
                                  "Wildcard ACAO with credentials=true (exploitable)"))
        elif acao == origin or acao == "null":
            msg = "Origin reflected"
            if acac == "true":
                msg += " with credentials=true"
            findings.append(_make(url, origin, acao, acac, msg))

    return findings


def _make(url, origin, acao, acac, detail) -> Dict[str, Any]:
    return {
        "type":      "cors",
        "severity":  "high" if "credentials" in detail else "medium",
        "url":       url,
        "parameter": "Origin",
        "payload":   origin,
        "context":   "cors-misconfiguration",
        "evidence":  f"ACAO: {acao}  ACAC: {acac}",
        "details":   detail,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
