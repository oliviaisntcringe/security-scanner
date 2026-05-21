"""
CSRF scanner — checks forms for missing/weak anti-CSRF tokens.
"""
from __future__ import annotations

import time
from typing import List, Dict, Any
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

from scanner.utils import http as http_util

CSRF_TOKEN_NAMES = {
    "csrf", "csrf_token", "_csrf", "csrfmiddlewaretoken",
    "_token", "authenticity_token", "xsrf", "xsrf_token",
    "__requestverificationtoken", "form_key", "nonce",
}

SAMESITE_PROTECT = {"strict", "lax"}


async def scan(session: aiohttp.ClientSession, url: str, forms=None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    # Check cookies for SameSite attribute
    resp = await http_util.get(session, url, timeout=10)
    if resp is None:
        return findings

    try:
        text = await resp.text(errors="ignore")
    except Exception:
        return findings

    cookie_findings = _check_cookies(resp, url)
    findings.extend(cookie_findings)

    soup = BeautifulSoup(text, "html.parser")
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue  # CSRF matters for state-changing requests

        action = form.get("action") or url
        inputs = {inp.get("name", "").lower(): inp for inp in form.find_all("input")}
        has_token = any(name in CSRF_TOKEN_NAMES for name in inputs)
        has_hidden_token = any(
            inp.get("type") == "hidden" and name in CSRF_TOKEN_NAMES
            for name, inp in inputs.items()
        )

        if not has_token:
            findings.append(_make_form(url, action, "No CSRF token in POST form"))
        elif not has_hidden_token:
            findings.append(_make_form(url, action, "CSRF token not in hidden field"))

    return findings


def _check_cookies(resp: aiohttp.ClientResponse, url: str) -> List[Dict[str, Any]]:
    findings = []
    for cookie in resp.cookies.values():
        samesite = (cookie.get("samesite") or "").lower()
        httponly = bool(cookie.get("httponly"))
        secure   = bool(cookie.get("secure"))
        name     = cookie.key

        issues = []
        if samesite not in SAMESITE_PROTECT:
            issues.append(f"SameSite={samesite or 'None'}")
        if not httponly:
            issues.append("HttpOnly missing")
        if url.startswith("https") and not secure:
            issues.append("Secure flag missing")

        if issues:
            findings.append({
                "type":      "csrf",
                "severity":  "medium",
                "url":       url,
                "parameter": name,
                "payload":   "N/A",
                "context":   "cookie-flags",
                "evidence":  f"Cookie '{name}': {', '.join(issues)}",
                "details":   "Cookie missing security attributes",
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
    return findings


def _make_form(url, action, evidence) -> Dict[str, Any]:
    return {
        "type":      "csrf",
        "severity":  "medium",
        "url":       url,
        "parameter": "form",
        "payload":   action,
        "context":   "missing-token",
        "evidence":  evidence,
        "details":   "CSRF protection missing or weak",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
