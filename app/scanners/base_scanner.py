import aiohttp
import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from ..utils.helpers import LOG
from ..config import USER_AGENT, MAX_SUBPAGES, MAX_RETRIES, SCAN_DELAY, ERROR_COOLDOWN, MAX_ERRORS_BEFORE_SKIP
from ..utils.spoofagent import get_spoofed_headers
from ..utils.proxy_manager import shared_proxy_manager
from ..utils.request_handler import make_request
import time
import random

class BaseScanner:
    def __init__(self):
        self.max_subpages = MAX_SUBPAGES
        self.session = None
        self.visited_urls = set()
        self.scanned_params = set()
        self.error_count = 0
        self.last_error_time = 0

    async def __aenter__(self):
        """Async context manager entry"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.cleanup()

    async def init_session(self):
        """Initialize aiohttp session"""
        if not self.session or self.session.closed:
            self.session = await shared_proxy_manager.get_session()
            if not self.session:
                # If no proxy available, create direct session
                connector = aiohttp.TCPConnector(ssl=False)
                self.session = aiohttp.ClientSession(
                    connector=connector,
                    headers=get_spoofed_headers()
                )

    async def cleanup(self):
        """Cleanup resources"""
        if self.session and not self.session.closed:
            await self.session.close()
            self.session = None

    async def crawl(self, base_url):
        """Base crawler implementation (async, using aiohttp)"""
        queue = [base_url]
        self.visited_urls = {base_url}
        self.scanned_params = set()

        try:
            await self.init_session()
            while queue and len(self.visited_urls) < self.max_subpages:
                url = queue.pop(0)
                try:
                    async with self.session.get(url, timeout=10) as response:
                        if response.status == 200:
                            text = await response.text()
                            soup = BeautifulSoup(text, 'html.parser')
                            
                            # Process forms
                            for form in soup.find_all('form'):
                                action = form.get('action', '')
                                if not action:  # Form submits to same URL
                                    action = url
                                elif not action.startswith('http'):  # Relative URL
                                    action = urljoin(url, action)
                                
                                method = form.get('method', 'get').lower()
                                inputs = {}
                                for input_tag in form.find_all('input'):
                                    name = input_tag.get('name')
                                    if name:
                                        inputs[name] = input_tag.get('value', '')
                                
                                self.scanned_params.add((action, method, inputs))
                                
                            # Add new URLs to queue
                            for link in soup.find_all('a', href=True):
                                href = link['href']
                                if not href.startswith('http'):
                                    href = urljoin(url, href)
                                if href not in self.visited_urls and href.startswith(base_url):
                                    self.visited_urls.add(href)
                                    queue.append(href)
                except Exception as e:
                    LOG(f"[!] Error crawling {url}: {e}")
        except Exception as e:
            LOG(f"[!] Crawl error: {e}")
        finally:
            await self.cleanup()

    async def test_vulnerability(self, url, payloads, check_response):
        """Generic vulnerability testing method (async, using aiohttp)"""
        params = self.get_injectable_params(url)
        try:
            await self.init_session()
            for param_name in params:
                for payload in payloads:
                    try:
                        test_params = {k: v for k, v in params.items()}
                        test_params[param_name] = payload
                        async with self.session.get(url, params=test_params, timeout=10) as r:
                            text = await r.text()
                            if check_response(text, payload):
                                return True, param_name, payload
                    except Exception as e:
                        LOG(f"[!] Test error: {e}")
        finally:
            await self.cleanup()
        return False, None, None

    def get_injectable_params(self, url):
        """Extract parameters that can be tested for injection"""
        parsed = urlparse(url)
        params = {}
        
        # URL parameters
        if parsed.query:
            from urllib.parse import parse_qs
            params.update(parse_qs(parsed.query))
            
        # Form parameters
        for furl, method, inputs in self.scanned_params:
            if furl == url:
                params.update(inputs)
                
        return params

    def should_skip_scan(self):
        """Check if we should skip scanning due to too many errors"""
        if self.error_count >= MAX_ERRORS_BEFORE_SKIP:
            if time.time() - self.last_error_time < ERROR_COOLDOWN:
                return True
            self.error_count = 0
        return False
    
    def handle_error(self, url, error):
        """Handle scanning errors with exponential backoff"""
        self.error_count += 1
        self.last_error_time = time.time()
        print(f"[!] Error scanning {url}: {str(error)}")
        
        # Exponential backoff
        if self.error_count > 1:
            sleep_time = min(300, 2 ** self.error_count + random.uniform(0, 1))
            print(f"[*] Backing off for {sleep_time:.1f} seconds")
            time.sleep(sleep_time)
    
    def scan_url(self, url, **kwargs):
        """Scan a URL with retries and error handling"""
        if self.should_skip_scan():
            print(f"[!] Skipping {url} due to too many recent errors")
            return None
            
        for attempt in range(MAX_RETRIES):
            try:
                response = make_request(url, **kwargs)
                if response is None:
                    continue
                    
                # Successful request, reset error count
                self.error_count = 0
                return response
                
            except Exception as e:
                self.handle_error(url, e)
                if attempt < MAX_RETRIES - 1:
                    continue
                break
                
            finally:
                time.sleep(SCAN_DELAY)
        
        return None

    def scan(self, target):
        """Main scanning method to be implemented by subclasses"""
        raise NotImplementedError 