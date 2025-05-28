import os
import time
import random
import aiohttp
import asyncio
import ssl
import certifi
try:
    import brotli
except ImportError:
    try:
        import Brotli as brotli  # type: ignore
    except ImportError:
        # If both imports fail, we'll handle it gracefully in the code
        brotli = None
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
from ..utils.helpers import LOG
from ..utils.proxy_manager import ProxyManager
from urllib.parse import quote_plus
from .spoofagent import get_spoofed_headers

class MultiSearchEngine:
    def __init__(self):
        self.search_backoff = 1
        self.session = None
        self.max_retries = 5
        self.timeout = aiohttp.ClientTimeout(total=60, connect=30)
        self.running = True
        self.current_page = 1
        self.results_per_page = 10
        self.proxy_manager = ProxyManager()
        self.retry_delays = [2, 4, 8, 16, 32]
        self.delay = 1  # Initial delay between requests
        self.max_delay = 30  # Maximum delay
        self.duckduckgo_endpoints = [
            'https://duckduckgo.com/html/',
            'https://html.duckduckgo.com/html/',
            'https://safe.duckduckgo.com/html/'
        ]
        self._proxy_rotation_task = None  # Do not start the task here
        
    async def __aenter__(self):
        """Async context manager entry"""
        await self._init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self._close_session()

    async def _init_session(self):
        """Initialize the session with proper error handling"""
        if not self.session or self.session.closed:
            try:
                # Create SSL context that ignores verification
                ssl_context = ssl._create_unverified_context()
                
                # Try to get a session with proxy
                self.session = await self.proxy_manager.get_session(ssl_context)
                
                # If no proxy available, create session without proxy
                if not self.session:
                    connector = aiohttp.TCPConnector(
                        ssl=False,  # Ignore SSL verification
                        force_close=True,
                        enable_cleanup_closed=True,
                        keepalive_timeout=30,
                        limit=10
                    )
                    self.session = aiohttp.ClientSession(
                        connector=connector, 
                        timeout=self.timeout,
                        headers=get_spoofed_headers() | {
                            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                            'Accept-Encoding': 'gzip, deflate',
                            'DNT': '1',
                            'Connection': 'close',
                            'Upgrade-Insecure-Requests': '1'
                        }
                    )
            except Exception as e:
                LOG(f"[!] Error initializing session: {e}")
                if self.session and not self.session.closed:
                    await self._close_session()
                raise

    async def _close_session(self):
        """Close the current session properly"""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                # Wait a bit for connections to close properly
                await asyncio.sleep(0.1)
            except Exception as e:
                LOG(f"[!] Error closing session: {e}")
            finally:
                self.session = None

    async def _retry_request(self, func, *args, **kwargs):
        """Generic retry mechanism for requests"""
        last_error = None
        current_proxy = None
        
        for attempt in range(self.max_retries):
            if not self.running:
                return None
                
            try:
                # Ensure we have a valid session
                await self._init_session()
                
                # Get current proxy for logging
                if self.session and hasattr(self.session, '_proxy'):
                    current_proxy = self.session._proxy
                    LOG(f"[*] Using proxy: {current_proxy}")
                
                # Add jitter to avoid overwhelming servers
                if attempt > 0:
                    jitter = random.uniform(0.1, 0.5)
                    await asyncio.sleep(jitter)
                
                result = await func(*args, **kwargs)
                
                # If request succeeded, reset backoff
                self.search_backoff = 1
                return result
                
            except (asyncio.TimeoutError, aiohttp.ClientError, ConnectionResetError) as e:
                last_error = e
                if current_proxy:
                    self.proxy_manager.remove_proxy(current_proxy)
                await self._close_session()  # Ensure session is closed on error
                if attempt == self.max_retries - 1:
                    raise
                wait_time = self.retry_delays[attempt]
                LOG(f"[*] Request failed ({str(e)}), retrying in {wait_time} seconds...")
                await asyncio.sleep(wait_time)

    async def search_bing(self, query, num_results=30):
        await self.ensure_proxy_rotation()
        """Search using Bing"""
        if not self.running:
            return []
            
        await self._init_session()
        all_results = []
        pages_to_fetch = (num_results + self.results_per_page - 1) // self.results_per_page
        
        for page in range(pages_to_fetch):
            if not self.running or len(all_results) >= num_results:
                break
                
            try:
                first_result = page * self.results_per_page + 1
                params = {
                    'q': query,
                    'first': str(first_result),
                    'count': str(self.results_per_page),
                    'form': 'QBLH'
                }
                
                async def _do_bing_request():
                    if not self.running:
                        return
                        
                    async with self.session.get('https://www.bing.com/search', 
                                             params=params) as response:
                        if response.status == 200:
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            # Find all search result containers
                            results = []
                            for result in soup.find_all(['li', 'div'], class_=['b_algo', 'b_title']):
                                # Try different ways to extract URLs
                                links = result.find_all('a', href=True)
                                for link in links:
                                    url = link.get('href', '')
                                    if url.startswith(('http://', 'https://')) and not any(x in url.lower() for x in ['bing.com', 'microsoft.com']):
                                        # Check if URL is not from same domain as existing results
                                        domain = url.split('/')[2]
                                        if not any(domain in existing_url for existing_url in all_results):
                                            results.append(url)
                                            LOG(f"[*] Found URL: {url}")
                            
                            return results
                        else:
                            LOG(f"[!] Bing search error: {response.status}")
                            return []
                
                page_results = await self._retry_request(_do_bing_request)
                if page_results:
                    all_results.extend(page_results)
                    LOG(f"[*] Found {len(page_results)} new results from Bing (page {page + 1})")
                    
                # Add delay between pages
                if page < pages_to_fetch - 1:
                    await asyncio.sleep(random.uniform(2, 4))
                    
            except Exception as e:
                LOG(f"[!] Bing search error on page {page + 1}: {str(e)}")
                break
                
        return list(set(all_results))  # Remove duplicates

    async def search_duckduckgo(self, query, max_results=20):
        await self.ensure_proxy_rotation()
        """Search using DuckDuckGo"""
        if not self.running:
            return []
            
        results = []
        seen_domains = set()
        ddg_timeout = aiohttp.ClientTimeout(total=45, connect=20)
        
        try:
            # First try the API approach with custom timeout
            try:
                # Use DDGS in a non-blocking way within a thread
                loop = asyncio.get_event_loop()
                search_results = await loop.run_in_executor(None, self._run_ddg_search, query, max_results)
                
                for url in search_results:
                    if not self.running:
                        break
                    
                    if url and url.startswith(('http://', 'https://')):
                        try:
                            domain = url.split('/')[2]
                            if domain not in seen_domains:
                                seen_domains.add(domain)
                                results.append(url)
                                LOG(f"[*] Found URL from DDG: {url}")
                        except Exception:
                            continue
            except Exception as e:
                LOG(f"[!] DuckDuckGo API search failed: {str(e)}")
                
                # Fallback to HTML scraping if API fails
                await self._init_session()
                
                async def _do_ddg_request():
                    if not self.running:
                        return []
                    
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                        'Accept-Encoding': 'gzip, deflate',
                        'DNT': '1',
                        'Connection': 'close'
                    }
                    
                    # Try different DuckDuckGo endpoints
                    endpoints = [
                        'https://html.duckduckgo.com/html',
                        'https://lite.duckduckgo.com/lite',
                        'https://duckduckgo.com/html'
                    ]
                    
                    for endpoint in endpoints:
                        if not self.running:
                            return []
                            
                        try:
                            params = {
                                'q': query,
                                'kl': 'us-en',
                                'kp': '1',
                                't': 'h_'  # HTML version
                            }
                            
                            async with self.session.get(endpoint, 
                                                      params=params,
                                                      headers=headers,
                                                      timeout=ddg_timeout,
                                                      allow_redirects=True) as response:
                                if response.status == 200:
                                    html = await response.text()
                                    soup = BeautifulSoup(html, 'html.parser')
                                    
                                    page_results = []
                                    # Try different result selectors
                                    selectors = [
                                        ('div', 'result__body'),
                                        ('div', 'links_main'),
                                        ('div', 'result-link')
                                    ]
                                    
                                    for tag, class_name in selectors:
                                        for result in soup.find_all(tag, class_=class_name):
                                            link = result.find('a')
                                            if link and link.get('href'):
                                                url = link['href']
                                                if url.startswith(('http://', 'https://')):
                                                    try:
                                                        domain = url.split('/')[2]
                                                        if domain not in seen_domains:
                                                            seen_domains.add(domain)
                                                            page_results.append(url)
                                                            LOG(f"[*] Found URL from DDG HTML: {url}")
                                                    except Exception:
                                                        continue
                                    
                                    if page_results:
                                        return page_results
                                elif response.status in (429, 202, 403, 503):
                                    LOG(f"[!] DuckDuckGo rate limit/block on {endpoint} ({response.status})")
                                    # Try next endpoint
                                    continue
                                else:
                                    LOG(f"[!] DuckDuckGo search error on {endpoint}: {response.status}")
                                    continue
                                    
                        except asyncio.TimeoutError:
                            LOG(f"[!] Timeout on {endpoint}, trying next...")
                            continue
                        except Exception as e:
                            LOG(f"[!] Error on {endpoint}: {str(e)}")
                            continue
                    
                    return []  # If all endpoints failed
                
                # Try HTML scraping with retries
                html_results = await self._retry_request(_do_ddg_request)
                if html_results:
                    results.extend(html_results)
                
        except Exception as e:
            LOG(f"[!] DuckDuckGo search error: {str(e)}")
            
        return list(set(results))  # Remove any duplicates

    def _run_ddg_search(self, query, max_results):
        """Run DuckDuckGo search in a blocking manner (for executor)"""
        urls = []
        try:
            with DDGS() as ddgs:
                results = list(ddgs.text(query, max_results=max_results))
                for r in results:
                    if isinstance(r, dict):
                        url = r.get('href')
                        if url:
                            urls.append(url)
        except Exception as e:
            LOG(f"[!] Error in DuckDuckGo search: {e}")
        return urls

    async def search_all(self, query, variations=[]):
        await self.ensure_proxy_rotation()
        """Search using all available engines"""
        results = set()
        
        # Add query variations
        queries = [query] + [f"{query} {var}" for var in variations]
        
        for q in queries:
            if not self.running:
                break
                
            try:
                # Search with DuckDuckGo
                results.update(await self._search_duckduckgo(q))
                
                # Add delay between queries
                if self.running:
                    await asyncio.sleep(self.delay)
                    
            except Exception as e:
                LOG(f"[!] Search error for '{q}': {e}")
                self.delay = min(self.delay * 2, self.max_delay)
                LOG(f"[*] Increasing search delay to {self.delay} seconds")
                
        return results
        
    async def _search_duckduckgo(self, query):
        """Search DuckDuckGo"""
        results = set()
        
        # Randomly select endpoint
        endpoint = random.choice(self.duckduckgo_endpoints)
        
        try:
            connector = aiohttp.TCPConnector(
                ssl=False,  # Ignore SSL verification
                force_close=True,
                enable_cleanup_closed=True
            )
            timeout = aiohttp.ClientTimeout(total=30)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=get_spoofed_headers() | {
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close'
                }
            ) as session:
                params = {
                    'q': query,
                    'kl': 'us-en',
                    't': 'h_',
                    'ia': 'web'
                }
                
                async with session.post(endpoint, data=params) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Extract results
                        for link in soup.select('.result__url'):
                            url = link.get('href', '')
                            if url and not any(x in url.lower() for x in ['duckduckgo.com', 'youtube.com', 'facebook.com']):
                                results.add(url)
                                
        except Exception as e:
            LOG(f"[!] DuckDuckGo search error: {e}")
            raise
            
        return results

    def stop(self):
        """Stop all ongoing searches and cleanup"""
        self.running = False

    def filter_results(self, urls, history=None):
        """Filter and clean search results"""
        if history is None:
            history = set()
            
        filtered_urls = []
        skip_domains = {
            'google.com', 'facebook.com', 'twitter.com', 'youtube.com',
            'instagram.com', 'linkedin.com', 'github.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'shopify.com'  # Added shopify.com to skip list
        }
        
        for url in urls:
            try:
                # Skip if already scanned
                if url in history:
                    continue
                    
                # Basic URL validation
                if not url.startswith(('http://', 'https://')):
                    continue
                    
                # Extract domain
                domain = url.split('/')[2].lower()
                
                # Skip common non-target URLs
                if any(skip in domain for skip in skip_domains):
                    continue
                    
                filtered_urls.append(url)
                
            except Exception:
                continue
            
        return filtered_urls 

    async def ensure_proxy_rotation(self):
        if self._proxy_rotation_task is None:
            self._proxy_rotation_task = asyncio.create_task(self._proxy_rotation_loop())

    async def _proxy_rotation_loop(self):
        while self.running:
            await asyncio.sleep(420)  # 7 minutes
            self.rotate_proxy()
            await self._close_session()
            await self._init_session()
            LOG('[*] Proxy rotated (every 7 minutes)')

    def rotate_proxy(self):
        """Rotate to a new proxy (to be implemented)"""
        # This is a placeholder. You can implement logic to pick a new proxy from ProxyManager.
        if hasattr(self.proxy_manager, 'update_proxies'):
            asyncio.create_task(self.proxy_manager.update_proxies())
        LOG('[*] Proxy rotation triggered.')

    async def cleanup(self):
        """Cleanup method to be called when done with the search engine"""
        await self._close_session() 