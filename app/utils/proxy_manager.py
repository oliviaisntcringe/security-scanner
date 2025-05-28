import aiohttp
import asyncio
import random
import json
import time
import ssl
import certifi
from bs4 import BeautifulSoup
from ..utils.helpers import LOG
from .spoofagent import get_spoofed_headers

class ProxyManager:
    def __init__(self):
        self.proxies = set()
        self.working_proxies = set()
        self.last_update = 0
        self.update_interval = 300  # 5 minutes
        self.check_url = 'http://www.google.com'
        self.timeout = aiohttp.ClientTimeout(total=10)
        self.ssl_context = ssl._create_unverified_context()
        
    async def update_proxies(self):
        """Update proxy list from multiple sources"""
        if time.time() - self.last_update < self.update_interval:
            return
            
        LOG("[*] Updating proxy list...")
        new_proxies = set()
        
        # Free Proxy List
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
            try:
                async with session.get('https://free-proxy-list.net/') as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        table = soup.find('table', {'id': 'proxylisttable'})
                        if not table:
                            # Try alternative selectors
                            table = soup.select_one('.table-striped')
                            if not table:
                                table = soup.find('table', {'class': 'table'})
                        if table:
                            rows = table.find_all('tr')[1:]
                            for row in rows:
                                cols = row.find_all('td')
                                if len(cols) > 6 and cols[6].text.strip() == 'yes':  # HTTPS proxy
                                    proxy = f"http://{cols[0].text}:{cols[1].text}"
                                    new_proxies.add(proxy)
                        else:
                            LOG("[!] Could not find proxy table in free-proxy-list.net response")
            except Exception as e:
                LOG(f"[!] Error fetching from free-proxy-list: {e}")
            
            # ProxyScrape API
            try:
                async with session.get('https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=yes&anonymity=elite&simplified=true') as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if line.strip():
                                new_proxies.add(f"http://{line.strip()}")
            except Exception as e:
                LOG(f"[!] Error fetching from proxyscrape: {e}")
            
            # Proxy-List.download API
            try:
                async with session.get('https://www.proxy-list.download/api/v1/get?type=https&anon=elite') as response:
                    if response.status == 200:
                        text = await response.text()
                        for line in text.split('\n'):
                            if line.strip():
                                new_proxies.add(f"http://{line.strip()}")
            except Exception as e:
                LOG(f"[!] Error fetching from proxy-list.download: {e}")
            
        if new_proxies:
            self.proxies.update(new_proxies)
            self.last_update = time.time()
            LOG(f"[*] Added {len(new_proxies)} new proxies. Total: {len(self.proxies)}")
        
    async def get_session(self, ssl_context=None):
        await self.update_proxies()
        if not self.proxies:
            return None
        session = None
        for _ in range(3):
            try:
                proxy = random.choice(list(self.proxies))
                connector = aiohttp.TCPConnector(ssl=False)
                session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=30),
                    headers=get_spoofed_headers() | {
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Encoding': 'gzip, deflate',
                        'Connection': 'close'
                    }
                )
                session._proxy = proxy

                # Test the proxy
                async with session.get(self.check_url, proxy=proxy) as response:
                    if response.status == 200:
                        return session
                
                # If we get here, the proxy didn't work
                await session.close()
                session = None
                self.proxies.discard(proxy)

            except Exception:
                if session and not session.closed:
                    await session.close()
                session = None
                self.proxies.discard(proxy)

        return None
        
    def remove_proxy(self, proxy):
        """Remove a non-working proxy"""
        self.proxies.discard(proxy)

shared_proxy_manager = ProxyManager() 