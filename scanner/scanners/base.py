"""
Base scanner — shared crawl + injectable-param extraction logic.
"""
from __future__ import annotations

import asyncio
from typing import List, Set, Dict, Tuple
from urllib.parse import urlparse, urljoin, parse_qs

import aiohttp
from bs4 import BeautifulSoup

from scanner.utils import http as http_util
from scanner.utils.output import info


class BaseScanner:
    def __init__(
        self,
        session: aiohttp.ClientSession,
        max_urls: int = 50,
        depth: int = 3,
    ) -> None:
        self.session = session
        self.max_urls = max_urls
        self.depth = depth
        self.visited: Set[str] = set()
        # (url, method, {field: value})
        self.forms: List[Tuple[str, str, Dict[str, str]]] = []

    # ── Crawl ──────────────────────────────────────────────────────────────────

    async def crawl(self, base_url: str) -> None:
        queue = [(base_url, 0)]
        self.visited = {base_url}
        base_domain = urlparse(base_url).netloc

        while queue and len(self.visited) < self.max_urls:
            url, depth = queue.pop(0)
            if depth > self.depth:
                continue

            resp = await http_util.get(self.session, url, timeout=15)
            if resp is None:
                continue

            try:
                text = await resp.text(errors="ignore")
            except Exception:
                continue

            soup = BeautifulSoup(text, "html.parser")

            # Collect forms
            for form in soup.find_all("form"):
                action = form.get("action") or url
                if not action.startswith("http"):
                    action = urljoin(url, action)
                method = (form.get("method") or "get").lower()
                fields: Dict[str, str] = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        fields[name] = inp.get("value", "test")
                self.forms.append((action, method, fields))

            # Follow links within same domain
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if not href.startswith("http"):
                    href = urljoin(url, href)
                parsed = urlparse(href)
                if parsed.netloc != base_domain:
                    continue
                clean = parsed._replace(fragment="").geturl()
                if clean not in self.visited and not self._skip(clean):
                    self.visited.add(clean)
                    queue.append((clean, depth + 1))

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _skip(self, url: str) -> bool:
        skip_ext = (".jpg", ".jpeg", ".png", ".gif", ".css", ".js",
                    ".svg", ".ico", ".woff", ".pdf", ".zip")
        skip_kw  = ("logout", "signout", "sign-out", "log-out")
        lurl = url.lower()
        return any(lurl.endswith(e) for e in skip_ext) or any(k in lurl for k in skip_kw)

    def urls_with_params(self) -> List[str]:
        """All crawled URLs that have query parameters."""
        return [u for u in self.visited if "?" in u]

    def injectable_urls(self) -> List[str]:
        return self.urls_with_params()
