"""
Shared async HTTP client with user-agent spoofing and optional proxy.
"""
from __future__ import annotations

import asyncio
import random
from typing import Optional

import aiohttp

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0",
]


def _headers(extra: Optional[dict] = None) -> dict:
    h = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }
    if extra:
        h.update(extra)
    return h


def make_session(proxy: Optional[str] = None, timeout: int = 30) -> aiohttp.ClientSession:
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    to = aiohttp.ClientTimeout(total=timeout)
    kwargs: dict = dict(connector=connector, timeout=to, headers=_headers())
    if proxy:
        kwargs["proxy"] = proxy
    return aiohttp.ClientSession(**kwargs)


async def get(
    session: aiohttp.ClientSession,
    url: str,
    params: Optional[dict] = None,
    headers: Optional[dict] = None,
    allow_redirects: bool = True,
    timeout: int = 15,
) -> Optional[aiohttp.ClientResponse]:
    """GET with silent error handling — returns None on failure."""
    try:
        resp = await asyncio.wait_for(
            session.get(url, params=params, headers=headers,
                        allow_redirects=allow_redirects),
            timeout=timeout,
        )
        return resp
    except Exception:
        return None


async def post(
    session: aiohttp.ClientSession,
    url: str,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    headers: Optional[dict] = None,
    timeout: int = 15,
) -> Optional[aiohttp.ClientResponse]:
    try:
        resp = await asyncio.wait_for(
            session.post(url, data=data, json=json, headers=headers),
            timeout=timeout,
        )
        return resp
    except Exception:
        return None
