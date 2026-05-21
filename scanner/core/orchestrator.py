"""
Scan orchestrator — coordinates crawl → scan → ML → report for one target.
"""
from __future__ import annotations

import asyncio
import time
from typing import List, Dict, Any, Optional, Set

import aiohttp

from scanner import config as cfg
from scanner.scanners.base import BaseScanner
from scanner.scanners import xss, sqli, ssrf, lfi, rce, csrf, cors, open_redirect
from scanner.ml.detector import MLDetector
from scanner.utils import http as http_util
from scanner.utils.output import info, warn, success, vuln as print_vuln, severity_of

# Map module name → async scan function
MODULES: Dict[str, Any] = {
    "xss":           xss.scan,
    "sqli":          sqli.scan,
    "ssrf":          ssrf.scan,
    "lfi":           lfi.scan,
    "rce":           rce.scan,
    "csrf":          csrf.scan,
    "cors":          cors.scan,
    "open_redirect": open_redirect.scan,
}


class ScanResult:
    def __init__(self, target: str) -> None:
        self.target    = target
        self.findings: List[Dict[str, Any]] = []
        self.errors:   List[str]            = []
        self.urls_crawled: int              = 0
        self.elapsed: float                 = 0.0
        self._seen: Set[tuple]              = set()

    def try_add(self, f: Dict[str, Any]) -> bool:
        """Add finding if not duplicate. Returns True if added (new finding)."""
        from urllib.parse import urlparse
        url   = f.get("url", "")
        # Deduplicate by (base_path_without_query, vuln_type, parameter)
        # so `index.jsp?content=A` and `index.jsp?content=B` aren't double-reported
        base  = urlparse(url)._replace(query="", fragment="").geturl()
        key   = (base, f.get("type", ""), f.get("parameter", ""))
        if key in self._seen:
            return False
        self._seen.add(key)
        self.findings.append(f)
        return True

    # keep backward compat
    def add(self, findings: List[Dict[str, Any]]) -> None:
        for f in findings:
            self.try_add(f)

    def summary(self) -> str:
        counts: Dict[str, int] = {}
        for f in self.findings:
            sev = f.get("severity", severity_of(f.get("type", "")))
            counts[sev] = counts.get(sev, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        return f"{len(self.findings)} findings ({', '.join(parts) or 'none'})"


class Orchestrator:
    def __init__(
        self,
        modules: Optional[List[str]] = None,
        depth: int = 3,
        max_urls: int = 50,
        threads: int = 5,
        proxy: Optional[str] = None,
        timeout: int = 30,
        use_ml: bool = True,
        verbose: bool = False,
        notify_each: bool = False,
    ) -> None:
        self.modules     = modules or list(MODULES.keys())
        self.depth       = depth
        self.max_urls    = max_urls
        self.threads     = threads
        self.proxy       = proxy
        self.timeout     = timeout
        self.use_ml      = use_ml
        self.verbose     = verbose
        self.notify_each = notify_each
        self._ml         = MLDetector() if use_ml else None
        self._sem        = asyncio.Semaphore(threads)

    async def scan_target(self, target: str) -> ScanResult:
        if not target.startswith(("http://", "https://")):
            target = "https://" + target

        result = ScanResult(target)
        t0 = time.monotonic()

        session = http_util.make_session(proxy=self.proxy, timeout=self.timeout)
        try:
            # ── Phase 1: Crawl ──────────────────────────────────────────────
            info(f"Crawling {target} …")
            crawler = BaseScanner(session, max_urls=self.max_urls, depth=self.depth)
            try:
                await asyncio.wait_for(crawler.crawl(target), timeout=120)
            except asyncio.TimeoutError:
                warn("Crawl timed out — continuing with discovered URLs")

            result.urls_crawled = len(crawler.visited)
            urls_with_params = crawler.injectable_urls()
            forms = crawler.forms

            if self.verbose:
                info(f"Crawled {result.urls_crawled} URLs, "
                     f"{len(urls_with_params)} injectable, "
                     f"{len(forms)} forms")

            # ── Phase 2: Scanner modules ────────────────────────────────────
            scan_targets = list(crawler.visited) if not urls_with_params else urls_with_params
            # Always include the root URL for CSRF/CORS checks
            if target not in scan_targets:
                scan_targets.insert(0, target)

            tasks = []
            for url in scan_targets[:self.max_urls]:
                for mod_name in self.modules:
                    fn = MODULES.get(mod_name)
                    if fn:
                        tasks.append(self._run_module(fn, session, url, forms, result))

            if tasks:
                await asyncio.gather(*tasks)

            # ── Phase 3: ML detection ───────────────────────────────────────
            if self.use_ml and self._ml and self._ml.available():
                info(f"Running ML detection on {min(10, len(scan_targets))} URLs …")
                ml_tasks = [
                    self._run_ml(session, url, result)
                    for url in scan_targets[:10]
                ]
                await asyncio.gather(*ml_tasks)

        finally:
            await session.close()

        result.elapsed = time.monotonic() - t0
        return result

    async def _run_module(self, fn, session, url, forms, result: ScanResult) -> None:
        async with self._sem:
            try:
                findings = await fn(session, url, forms)
                for f in (findings or []):
                    if result.try_add(f):          # only print/notify new unique findings
                        print_vuln(f)
                        if self.notify_each:
                            from scanner.utils.notify import notify_vuln
                            await notify_vuln(f)
            except Exception as e:
                result.errors.append(str(e))

    async def _run_ml(self, session, url, result: ScanResult) -> None:
        async with self._sem:
            try:
                findings = await self._ml.scan(session, url)
                for f in (findings or []):
                    if result.try_add(f):
                        print_vuln(f)
            except Exception as e:
                result.errors.append(str(e))
