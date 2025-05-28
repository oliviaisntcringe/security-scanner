import numpy as np
import asyncio
import aiohttp
import json
from bs4 import BeautifulSoup
import re
import pickle
import os
import traceback
import time
import random
from ..utils.helpers import LOG, save_ml_detection
from ..config import ML_MODELS_PATH, ML_CONFIDENCE_THRESHOLD, ML_DEBUG, RETRY_COUNT, RETRY_DELAY, ML_MIN_FEATURES, RESULTS_DIR

class MLScanner:
    """The machine mind sees patterns humans miss. It finds the invisible cracks in their systems."""
    
    def __init__(self):
        self.models = {}
        self.features = {}
        self.scalers = {}  # The reality distortion field
        self.load_models()
        self.visited_urls = set()
        self.session = None
        self.debug_info = {}
        self.vulnerability_count = 0
        
    async def __aenter__(self):
        """Wake up the digital consciousness. It's time to hunt."""
        await self.init_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Put the ghost back in the machine. Leave no trace."""
        await self.cleanup()

    async def init_session(self):
        """Open a new connection. They track persistence. New identity each time. Stay anonymous."""
        if not self.session or self.session.closed:
            try:
                self.session = aiohttp.ClientSession(
                    connector=aiohttp.TCPConnector(ssl=False),
                    timeout=aiohttp.ClientTimeout(total=30)
                )
                LOG("[*] ML scanner network session established")
            except Exception as e:
                LOG(f"[!] ML scanner session initialization failed: {e}")
                self.session = None

    async def cleanup(self):
        """Delete the footprints. We were never here. End the session. Terminate connections."""
        if self.session and not self.session.closed:
            try:
                await self.session.close()
                LOG("[*] ML scanner network session terminated")
            except Exception as e:
                LOG(f"[!] ML scanner cleanup error: {e}")
            finally:
                self.session = None

    def load_models(self):
        """Load the neural networks. The digital mind that sees the invisible. The patterns in the chaos."""
        model_types = ['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'rce']
        
        if not os.path.exists(ML_MODELS_PATH):
            os.makedirs(ML_MODELS_PATH)
            LOG("[!] Brain storage directory initialized")
            return
            
        for model_type in model_types:
            try:
                # Loading the binary brain components
                model_path = os.path.join(ML_MODELS_PATH, f"{model_type}_model.pkl")
                features_path = os.path.join(ML_MODELS_PATH, f"{model_type}_features.pkl")
                scaler_path = os.path.join(ML_MODELS_PATH, f"{model_type}_scaler.pkl")
                
                if all(os.path.exists(p) for p in [model_path, features_path, scaler_path]):
                    with open(model_path, 'rb') as f:
                        self.models[model_type] = pickle.load(f)
                    with open(features_path, 'rb') as f:
                        self.features[model_type] = pickle.load(f)
                    with open(scaler_path, 'rb') as f:
                        self.scalers[model_type] = pickle.load(f)
                    LOG(f"[*] Neural network {model_type} loaded and armed")
                else:
                    LOG(f"[!] Missing neural patterns for {model_type}")
            except Exception as e:
                LOG(f"[!] Brain component failure for {model_type}: {e}")
                if ML_DEBUG:
                    LOG(f"[!] Neural error trace: {traceback.format_exc()}")

    async def crawl(self, url):
        """Map their digital kingdom. Find all entries, exits, secret passages. Nothing's truly locked."""
        if not url:
            return
            
        self.visited_urls.add(url)
        try:
            # New identity for each crawl. Don't let them connect the dots.
            connector = aiohttp.TCPConnector(ssl=False)
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                try:
                    async with session.get(url, timeout=30, verify_ssl=False) as response:
                        if response.status == 200:
                            html = await response.text()
                            soup = BeautifulSoup(html, 'html.parser')
                            
                            # Find all the rabbit holes
                            for a_tag in soup.find_all('a', href=True):
                                href = a_tag['href']
                                if href.startswith('http'):
                                    if self._is_same_domain(url, href):
                                        self.visited_urls.add(href)
                                elif href.startswith('/'):
                                    base_url = self._get_base_url(url)
                                    full_url = f"{base_url}{href}"
                                    self.visited_urls.add(full_url)
                            
                            # Locate all points of data entry. Where users pour their secrets.
                            for form in soup.find_all('form'):
                                action = form.get('action', '')
                                if action.startswith('http'):
                                    if self._is_same_domain(url, action):
                                        self.visited_urls.add(action)
                                elif action.startswith('/') or action == '':
                                    base_url = self._get_base_url(url)
                                    if action == '':
                                        full_url = url
                                    else:
                                        full_url = f"{base_url}{action}"
                                    self.visited_urls.add(full_url)
                            
                            LOG(f"[*] Neural mapper identified {len(self.visited_urls)} access vectors in {url}")
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    LOG(f"[!] Neural crawling error on {url}: {str(e)}")
                except Exception as e:
                    LOG(f"[!] Neural crawling exception on {url}: {str(e)}")
                    if ML_DEBUG:
                        LOG(f"[!] Neural crawler trace: {traceback.format_exc()}")
        except Exception as e:
            LOG(f"[!] Neural mapping disrupted on {url}: {e}")
    
    def _is_same_domain(self, url1, url2):
        """Stay within territory bounds. Don't cross borders. Keep to the target domain."""
        try:
            domain1 = url1.split('/')[2] if len(url1.split('/')) > 2 else ''
            domain2 = url2.split('/')[2] if len(url2.split('/')) > 2 else ''
            return domain1 == domain2
        except Exception:
            return False
    
    def _get_base_url(self, url):
        """Extract the root domain. The foundation. The home base."""
        try:
            parts = url.split('/')
            if len(parts) >= 3:
                return f"{parts[0]}//{parts[2]}"
            return url
        except Exception:
            return url
    
    async def extract_features(self, url, vulnerability_type):
        """Find the patterns in their system. The anomalies. The weaknesses. The entropy in their order."""
        max_retries = RETRY_COUNT if 'RETRY_COUNT' in globals() else 3
        retry_count = 0
        retry_error = None
        
        while retry_count < max_retries:
            try:
                # Each connection is an anonymous mask. A new identity.
                connector = aiohttp.TCPConnector(
                    ssl=False,               # SSL certificates are just corporate lies
                    force_close=True,        # Don't leave the connection open. Cut the cord.
                    enable_cleanup_closed=True, # Clean up after yourself. No digital fingerprints.
                    limit=10,                # Spread connections. Be unpredictable.
                    ttl_dns_cache=300        # Cache DNS. Fewer requests. Less visibility.
                )
                timeout = aiohttp.ClientTimeout(
                    total=45,                # Give it time. Patience.
                    connect=10,              # Time to establish connection
                    sock_read=30,            # Time to read data
                    sock_connect=10          # Time to connect to socket
                )
                async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                    try:
                        async with session.get(url, timeout=timeout, verify_ssl=False, allow_redirects=True) as response:
                            if response.status == 200:
                                try:
                                    try:
                                        html = await response.text()
                                    except UnicodeDecodeError as decode_error:
                                        # Digital babel. Language barriers. Force the translation.
                                        LOG(f"[!] Character encoding error: {decode_error}. Trying with 'latin-1' encoding.")
                                        # Try with a different cipher
                                        html = await response.read()
                                        html = html.decode('latin-1', errors='replace')
                                    
                                    soup = BeautifulSoup(html, 'html.parser')
                                    
                                    # Universal weakness indicators - the system's vital signs
                                    feature_vector = [
                                        len(html),  # Data volume - large surfaces hide more flaws
                                        len(re.findall(r'<input', html, re.IGNORECASE)),  # Input channels - each one a potential exploit
                                        len(re.findall(r'<form', html, re.IGNORECASE)),  # Form elements - attack vectors
                                        len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JS protocol usage - signs of weak protection
                                        len(soup.find_all('script')),  # Script elements - client-side attack surface
                                        len(soup.find_all('iframe')),  # Iframes - trust boundaries
                                        len(soup.find_all('a', href=True)),  # Anchor links - network pathways
                                        len(soup.find_all('meta')),  # Meta tags - system metadata
                                        len(soup.find_all('link')),  # Link tags - external dependencies
                                        len(re.findall(r'function\s*\(', html))  # JS functions - code execution points
                                    ]
                                    
                                    # Vulnerability-specific weakness indicators
                                    if vulnerability_type == 'xss':
                                        feature_vector.extend([
                                            # Event handlers - code injection points
                                            len(re.findall(r'onerror', html, re.IGNORECASE)),
                                            len(re.findall(r'onload', html, re.IGNORECASE)),
                                            len(re.findall(r'onclick', html, re.IGNORECASE)),
                                            len(re.findall(r'onmouseover', html, re.IGNORECASE)),
                                            len(re.findall(r'onmouseout', html, re.IGNORECASE)),
                                            len(re.findall(r'onkeyup', html, re.IGNORECASE)),
                                            len(re.findall(r'onkeydown', html, re.IGNORECASE)),
                                            len(re.findall(r'onsubmit', html, re.IGNORECASE)),
                                            len(re.findall(r'onchange', html, re.IGNORECASE)),
                                            len(re.findall(r'onfocus', html, re.IGNORECASE)),
                                            
                                            # JS execution functions - trusted entry points
                                            len(re.findall(r'eval\(', html, re.IGNORECASE)),
                                            len(re.findall(r'setTimeout\(', html, re.IGNORECASE)),
                                            len(re.findall(r'setInterval\(', html, re.IGNORECASE)),
                                            len(re.findall(r'document\.write\(', html, re.IGNORECASE)),
                                            len(re.findall(r'\.innerHTML', html, re.IGNORECASE)),
                                            len(re.findall(r'\.outerHTML', html, re.IGNORECASE)),
                                            len(re.findall(r'\.insertAdjacentHTML', html, re.IGNORECASE)),
                                            len(re.findall(r'\.execScript', html, re.IGNORECASE)),
                                        ])
                                    elif vulnerability_type == 'sqli':
                                        feature_vector.extend([
                                            # SQL injection markers - database exposure points
                                            len(re.findall(r'select.*from', html, re.IGNORECASE)),
                                            len(re.findall(r'insert.*into', html, re.IGNORECASE)),
                                            len(re.findall(r'update.*set', html, re.IGNORECASE)),
                                            len(re.findall(r'delete.*from', html, re.IGNORECASE)),
                                            len(re.findall(r'drop.*table', html, re.IGNORECASE)),
                                            len(re.findall(r'database\(', html, re.IGNORECASE)),
                                            len(re.findall(r'exec[\s\(]', html, re.IGNORECASE)),
                                            len(re.findall(r'execute[\s\(]', html, re.IGNORECASE)),
                                            1 if re.search(r'union select', html, re.IGNORECASE) else 0,
                                            1 if re.search(r'order by', html, re.IGNORECASE) else 0,
                                            1 if re.search(r'group by', html, re.IGNORECASE) else 0,
                                            1 if re.search(r'having', html, re.IGNORECASE) else 0,
                                            1 if re.search(r'limit', html, re.IGNORECASE) else 0,
                                            1 if ';' in url else 0,
                                            1 if re.search(r'%27|%23|%2F\*', url.lower()) else 0,
                                            1 if 'cookie' in html.lower() and re.search(r'1=1|or|and', html.lower()) else 0,
                                            1 if 'user-agent' in html.lower() and re.search(r'1=1|or|and', html.lower()) else 0,
                                            1 if re.search(r'json.*error', html.lower()) else 0,
                                            1 if re.search(r'(--|#|/\*)', url) else 0,
                                            1 if re.search(r'(sleep|benchmark|pg_sleep|waitfor\s+delay)', url.lower()) else 0,
                                            1 if re.search(r'(and\s+\d+=\d+|or\s+\d+=\d+)', url.lower()) else 0,
                                            1 if "'" in url or '"' in url else 0,
                                            1 if re.search(r'(concat\(|concat_ws\(|group_concat\()', url.lower()) else 0,
                                            1 if 'information_schema' in url.lower() else 0,
                                            1 if re.search(r'(sys\.tables|sys\.objects|all_tables|user_tables)', url.lower()) else 0,
                                            1 if re.search(r'(case\s+when|decode\()', url.lower()) else 0,
                                            1 if re.search(r'[?&]id=', url.lower()) else 0,
                                            len(re.findall(r'[?&][a-z]+=[0-9]+', url.lower())),
                                            len(html),
                                            1 if '200 OK' in html else 0,
                                            1 if '500 Internal Server Error' in html else 0,
                                            1 if '403 Forbidden' in html else 0,
                                            1 if re.search(r'waf|firewall|blocked|captcha', html.lower()) else 0,
                                            1 if any('id=' in (f.get('action') or '') for f in soup.find_all('form')) else 0,
                                            1 if any('id=' in (s.string or '') for s in soup.find_all('script')) else 0,
                                            1 if any('id=' in (a.get('href') or '') for a in soup.find_all('a')) else 0,
                                            1 if 'id=' in html.lower() and 'header' in html.lower() else 0,
                                            1 if 'id=' in html.lower() and 'cookie' in html.lower() else 0
                                        ])
                                    elif vulnerability_type == 'csrf':
                                        feature_vector.extend([
                                            # CSRF protection indicators - or lack thereof
                                            1 if re.search(r'csrf', html, re.IGNORECASE) else 0,
                                            1 if re.search(r'token', html, re.IGNORECASE) else 0,
                                            len(soup.find_all('form')),
                                            len(soup.find_all('input', {'type': 'hidden'})),
                                            1 if re.search(r'sameorigin', html, re.IGNORECASE) else 0,
                                            
                                            # State-changing operations - key CSRF targets
                                            1 if 'POST' in html else 0,
                                            1 if 'method="post"' in html.lower() else 0,
                                            1 if 'action=' in html.lower() else 0,
                                            len(re.findall(r'submit\(\)', html)),
                                            len(re.findall(r'ajax\(', html)),
                                        ])
                                    elif vulnerability_type == 'ssrf':
                                        feature_vector.extend([
                                            # Server-side request indicators
                                            len(re.findall(r'curl_', html, re.IGNORECASE)),
                                            len(re.findall(r'file_get_contents', html, re.IGNORECASE)),
                                            len(re.findall(r'http_request', html, re.IGNORECASE)),
                                            len(re.findall(r'urllib', html, re.IGNORECASE)),
                                            len(re.findall(r'requests\.', html, re.IGNORECASE)),
                                            len(re.findall(r'fetch\(', html, re.IGNORECASE)),
                                            
                                            # URL parameters - potential SSRF vectors
                                            1 if 'url=' in url else 0,
                                            1 if 'path=' in url else 0,
                                            1 if 'file=' in url else 0,
                                            1 if 'dest=' in url else 0,
                                            1 if 'redirect=' in url else 0,
                                            1 if 'uri=' in url else 0,
                                            1 if 'source=' in url else 0,
                                            1 if 'callback=' in url else 0,
                                            1 if re.search(r'[?&](url|site|path|callback|webhook|dest|redirect|uri|fetch|load|resource|domain|host|website|feed|to|out|image|link|proxy|forward|remote|open)=', url.lower()) else 0,
                                            len(url.split('?')[1].split('&')) if '?' in url else 0,
                                            1 if re.search(r'url=', html.lower()) else 0,
                                            1 if 'gopher://' in url.lower() else 0,
                                            1 if 'dict://' in url.lower() else 0,
                                            1 if 'smb://' in url.lower() else 0,
                                            1 if 'ldap://' in url.lower() else 0,
                                            1 if 'file://' in url.lower() else 0,
                                            1 if 'php://' in url.lower() else 0,
                                            1 if re.search(r'169.254.169.254|metadata.google.internal|metadata.azure.com|100.100.100.200', url.lower()) else 0,
                                            1 if re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|localhost.localdomain', url.lower()) else 0,
                                            1 if re.search(r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.', url) else 0,
                                            1 if re.search(r'0x[a-f0-9]{8}', url.lower()) else 0,
                                            1 if re.search(r'\d{8,10}', url) else 0,
                                            1 if '[' in url and ']' in url else 0,
                                            1 if '@' in url else 0,
                                            1 if re.search(r'rebind|dynamic\.dns', url.lower()) else 0,
                                            1 if 'x-forwarded-for' in html.lower() else 0,
                                            1 if 'host:' in html.lower() else 0,
                                            1 if 'location:' in html.lower() else 0,
                                            1 if html.lower().count('redirect') > 1 else 0,
                                            1 if re.search(r'connection refused|timeout|no route to host|invalid url|refused to connect', html.lower()) else 0,
                                            1 if re.search(r'ami-id|instance-id|hostname|access-key', html.lower()) else 0,
                                            1 if re.search(r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|localhost|127\.0\.0\.1', html.lower()) else 0,
                                            0,  # response_time (можно добавить при интеграции с реальным запросом)
                                            len(html),
                                            html.lower().count('location:'),
                                            1 if any('url=' in (f.get('action') or '') for f in soup.find_all('form')) else 0,
                                            1 if any('url=' in (s.string or '') for s in soup.find_all('script')) else 0,
                                            1 if any('url=' in (a.get('href') or '') for a in soup.find_all('a')) else 0,
                                            1 if 'url=' in html.lower() and 'header' in html.lower() else 0,
                                            1 if 'url=' in html.lower() and 'cookie' in html.lower() else 0
                                        ])
                                    elif vulnerability_type == 'lfi':
                                        feature_vector.extend([
                                            # Local file inclusion indicators
                                            1 if 'file=' in url else 0,
                                            1 if 'path=' in url else 0,
                                            1 if 'dir=' in url else 0,
                                            1 if 'include=' in url else 0,
                                            1 if 'require=' in url else 0,
                                            1 if 'doc=' in url else 0,
                                            
                                            # Directory traversal patterns
                                            len(re.findall(r'\.\./', url)),
                                            len(re.findall(r'\.\.\\', url)),
                                            
                                            # File operation hints in page
                                            len(re.findall(r'fopen', html, re.IGNORECASE)),
                                            len(re.findall(r'readfile', html, re.IGNORECASE)),
                                            len(re.findall(r'file_', html, re.IGNORECASE)),
                                            len(re.findall(r'include\(', html, re.IGNORECASE)),
                                            len(re.findall(r'require\(', html, re.IGNORECASE)),
                                            len(re.findall(r'include_once', html, re.IGNORECASE)),
                                        ])
                                    elif vulnerability_type == 'rce':
                                        feature_vector.extend([
                                            # Command execution indicators
                                            len(re.findall(r'exec\(', html, re.IGNORECASE)),
                                            len(re.findall(r'shell_exec', html, re.IGNORECASE)),
                                            len(re.findall(r'system\(', html, re.IGNORECASE)),
                                            len(re.findall(r'passthru', html, re.IGNORECASE)),
                                            len(re.findall(r'proc_open', html, re.IGNORECASE)),
                                            len(re.findall(r'popen', html, re.IGNORECASE)),
                                            len(re.findall(r'eval\(', html, re.IGNORECASE)),
                                            
                                            # Command parameters in URL
                                            1 if 'cmd=' in url else 0,
                                            1 if 'command=' in url else 0,
                                            1 if 'exec=' in url else 0,
                                            1 if 'execute=' in url else 0,
                                            1 if 'ping=' in url else 0,
                                            1 if 'query=' in url else 0,
                                            1 if 'jump=' in url else 0,
                                            1 if 'code=' in url else 0,
                                        ])
                                    
                                    # Feature vector length verification
                                    if vulnerability_type in self.models:
                                        try:
                                            # Get expected feature count from model
                                            model = self.models[vulnerability_type]
                                            expected_features = model.n_features_in_ if hasattr(model, 'n_features_in_') else 0
                                            
                                            # If still zero, try from default config
                                            if expected_features == 0:
                                                if isinstance(ML_MIN_FEATURES, dict):
                                                    expected_features = ML_MIN_FEATURES.get(vulnerability_type, 30)
                                                else:
                                                    expected_features = ML_MIN_FEATURES if ML_MIN_FEATURES > 0 else 30
                                            
                                            # Verify and pad as needed
                                            if len(feature_vector) < expected_features:
                                                LOG(f"[!] Neural pattern input insufficient: {len(feature_vector)} < {expected_features}, padding with zeros")
                                                # Extend with zeros to meet required length
                                                feature_vector.extend([0] * (expected_features - len(feature_vector)))
                                        except Exception as e:
                                            LOG(f"[!] Error determining feature count for {vulnerability_type}: {e}")
                                            # Default padding to a reasonable size
                                            if len(feature_vector) < 40:
                                                feature_vector.extend([0] * (40 - len(feature_vector)))
                                    
                                    # Feature vector as array
                                    feature_array = np.array(feature_vector).reshape(1, -1)
                                    
                                    # Normalize against human detection algorithms
                                    if vulnerability_type in self.scalers:
                                        try:
                                            feature_array = self.scalers[vulnerability_type].transform(feature_array)
                                        except Exception as e:
                                            LOG(f"[!] Neural scaling error for {vulnerability_type}: {e}")
                                            # Fallback to standard normalization
                                            from sklearn.preprocessing import StandardScaler
                                            scaler = StandardScaler()
                                            feature_array = scaler.fit_transform(feature_array)
                                    
                                    # Store debug info if enabled
                                    if ML_DEBUG:
                                        self.debug_info[url] = {
                                            'vulnerability_type': vulnerability_type,
                                            'features': feature_vector,
                                            'feature_names': self.features.get(vulnerability_type, []),
                                            'html_length': len(html)
                                        }
                                    
                                    LOG(f"[+] Neural patterns extracted for {vulnerability_type} from {url} - {len(feature_vector)} features")
                                    return feature_array
                                    
                                except Exception as e:
                                    retry_error = f"Feature extraction error on {url}: {str(e)}"
                                    LOG(f"[!] {retry_error}")
                                    if ML_DEBUG:
                                        LOG(f"[!] Neural error trace: {traceback.format_exc()}")
                            else:
                                retry_error = f"Non-200 response from {url}: {response.status}"
                                LOG(f"[!] {retry_error}")
                    except aiohttp.ClientError as e:
                        retry_error = f"Connection error on {url}: {str(e)}"
                        LOG(f"[!] {retry_error}")
                    except asyncio.TimeoutError:
                        retry_error = f"Connection timeout on {url}"
                        LOG(f"[!] {retry_error}")
                        
                # Implement exponential backoff with jitter - avoid detection patterns
                retry_count += 1
                if retry_count < max_retries:
                    # Calculate backoff time with jitter
                    backoff_time = RETRY_DELAY * (2 ** (retry_count - 1))  # Exponential backoff
                    jitter = random.uniform(0, 0.5 * backoff_time)  # Random jitter up to 50%
                    wait_time = backoff_time + jitter
                    LOG(f"[*] Neural retry {retry_count}/{max_retries} for {url} in {wait_time:.2f}s")
                    await asyncio.sleep(wait_time)
                        
            except Exception as e:
                LOG(f"[!] Critical neural extraction error: {str(e)}")
                if ML_DEBUG:
                    LOG(f"[!] Neural fault trace: {traceback.format_exc()}")
                retry_count += 1
                await asyncio.sleep(RETRY_DELAY)
        
        # If we're here, all retries failed
        LOG(f"[!] All neural extraction attempts failed for {url}: {retry_error}")
        return None
                
    async def predict_vulnerability(self, url, vulnerability_type):
        """Predict target system vulnerabilities using neural networks"""
        if vulnerability_type not in self.models:
            LOG(f"[!] Neural network model for {vulnerability_type} not loaded")
            return None
            
        try:
            # Extract system weakness signatures
            features = await self.extract_features(url, vulnerability_type)
            if features is None:
                LOG(f"[!] Failed to extract neural patterns from {url}")
                return None
            
            # Get model's expected feature count
            model = self.models[vulnerability_type]
            expected_features = None
            
            # Try to get the expected feature count from different model types
            if hasattr(model, 'n_features_in_'):
                expected_features = model.n_features_in_
            elif hasattr(model, 'feature_importances_'):
                expected_features = len(model.feature_importances_)
            elif hasattr(model, 'coef_') and model.coef_ is not None:
                if len(model.coef_.shape) > 1:
                    expected_features = model.coef_.shape[1]
                else:
                    expected_features = model.coef_.shape[0]
            
            # Handle feature count mismatch
            if expected_features is not None and len(features[0]) != expected_features:
                LOG(f"[*] Feature count mismatch for {vulnerability_type}: got {len(features[0])}, expected {expected_features}")
                # Adjust feature vector to match model's expectations
                if len(features[0]) > expected_features:
                    # Truncate extra features if we have more than needed
                    features = features[:, :expected_features]
                    LOG(f"[*] Truncated feature vector to {expected_features} features")
                else:
                    # Pad with zeros if we have fewer features than expected
                    padding = np.zeros((features.shape[0], expected_features - features.shape[1]))
                    features = np.hstack((features, padding))
                    LOG(f"[*] Padded feature vector to {expected_features} features")
            
            # Apply scaling if available, but only after we've adjusted the feature count
            if vulnerability_type in self.scalers:
                scaler = self.scalers[vulnerability_type]
                try:
                    # Now that features should match the expected count, scaling should work
                    features = scaler.transform(features)
                except Exception as e:
                    LOG(f"[!] Neural scaling error for {vulnerability_type}: {str(e)}")
                    # Continue without scaling
            
            # Apply prediction algorithm
            try:
                prediction = model.predict(features)[0]
                
                # For some models, we also want prediction probabilities
                if hasattr(model, 'predict_proba'):
                    probabilities = model.predict_proba(features)[0]
                    confidence = probabilities[1] if prediction == 1 and len(probabilities) > 1 else 0
                else:
                    confidence = 0.5  # Default confidence
                
                # Filter low-confidence predictions - reduce false patterns
                if isinstance(ML_CONFIDENCE_THRESHOLD, dict):
                    threshold = ML_CONFIDENCE_THRESHOLD.get(vulnerability_type, 0.7)
                else:
                    threshold = ML_CONFIDENCE_THRESHOLD if isinstance(ML_CONFIDENCE_THRESHOLD, float) else 0.7
                
                if prediction == 1 and confidence >= threshold:
                    LOG(f"[*] Neural detection: {vulnerability_type} vulnerability in {url} - {confidence:.2f} confidence")
                    self.vulnerability_count += 1
                    
                    # Create detailed evidence based on vulnerability type
                    evidence = "The ML model detected patterns consistent with this vulnerability type based on: "
                    
                    if vulnerability_type == 'xss':
                        evidence += "JavaScript event handlers, DOM manipulation methods, or user input reflection patterns."
                        example_payload = "<script>alert('XSS')</script>"
                    elif vulnerability_type == 'sqli':
                        evidence += "Database query patterns, SQL-like syntax in parameters, or error-based SQL signatures."
                        example_payload = "' OR 1=1; --"
                    elif vulnerability_type == 'csrf':
                        evidence += "Missing CSRF tokens, form submission patterns without proper protection."
                        example_payload = "Cross-site form submission"
                    elif vulnerability_type == 'ssrf':
                        evidence += "URL parameters that could be manipulated for server-side requests."
                        example_payload = "http://internal-server/admin"
                    elif vulnerability_type == 'lfi':
                        evidence += "Path traversal opportunities, file inclusion patterns."
                        example_payload = "../../../etc/passwd"
                    elif vulnerability_type == 'rce':
                        evidence += "Command execution patterns, dangerous function usage."
                        example_payload = "; cat /etc/passwd"
                    else:
                        evidence += "Structural patterns and code signatures associated with security weaknesses."
                        example_payload = "Generic attack vector"
                    
                    result = {
                        'type': vulnerability_type,
                        'url': url,
                        'confidence': confidence,
                        'predicted': True,
                        'details': f"ML model detected {vulnerability_type} vulnerability with {confidence:.2f} confidence",
                        'parameter': 'Multiple potential parameters detected',
                        'payload': f"Example: {example_payload} (Not actually used - ML detection is non-intrusive)",
                        'evidence': evidence,
                        'detected_by': 'machine_learning',
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    # Directly save the vulnerability
                    save_ml_detection(
                        vulnerability_type, 
                        url, 
                        confidence, 
                        f"ML model detected {vulnerability_type} vulnerability with {confidence:.2f} confidence"
                    )
                    
                    return result
                return None
            except Exception as e:
                LOG(f"[!] Neural prediction error for {vulnerability_type} on {url}: {str(e)}")
                if ML_DEBUG:
                    LOG(f"[!] Neural fault trace: {traceback.format_exc()}")
                return None
                
        except Exception as e:
            LOG(f"[!] Neural prediction error for {vulnerability_type} on {url}: {str(e)}")
            if ML_DEBUG:
                LOG(f"[!] Neural fault trace: {traceback.format_exc()}")
            return None

    async def scan_all(self, url):
        """Execute full neural scan array against target system"""
        # Ensure we have a session
        await self.init_session()
        
        # Reset vulnerability counter
        self.vulnerability_count = 0
        
        # All vulnerability types we can detect
        vuln_types = ['xss', 'sqli', 'csrf', 'ssrf', 'lfi', 'rce']
        
        # First crawl to discover attack surfaces
        await self.crawl(url)
        
        # Initialize results container
        findings = []
        
        # Limit URLs to avoid excessive scanning
        scan_urls = list(self.visited_urls)
        if len(scan_urls) > 30:
            LOG(f"[*] Limiting ML scan to 30 URLs from {len(scan_urls)} discovered")
            scan_urls = scan_urls[:30]
        
        # Scan each discovered URL with each neural network
        total_urls = len(scan_urls)
        processed = 0
        
        LOG(f"[*] ML scanner starting analysis of {total_urls} URLs")
        
        for discovered_url in scan_urls:
            processed += 1
            if processed % 5 == 0:
                LOG(f"[*] ML scan progress: {processed}/{total_urls} URLs ({(processed/total_urls)*100:.0f}%)")
                
            for vuln_type in vuln_types:
                if vuln_type in self.models:
                    result = await self.predict_vulnerability(discovered_url, vuln_type)
                    if result:
                        findings.append(result)
        
        # Directly save detected vulnerabilities to the consolidated file
        if findings:
            # Create consolidated file for vulnerabilities
            consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
            os.makedirs(RESULTS_DIR, exist_ok=True)
            
            all_vulns = {'vulnerabilities': []}
            
            # Load existing consolidated file if it exists
            if os.path.exists(consolidated_file):
                try:
                    with open(consolidated_file, 'r') as f:
                        all_vulns = json.load(f)
                        if not isinstance(all_vulns, dict) or 'vulnerabilities' not in all_vulns:
                            all_vulns = {'vulnerabilities': []}
                except Exception as e:
                    LOG(f"[!] Error reading consolidated vulnerabilities file: {e}")
                    all_vulns = {'vulnerabilities': []}
            
            # Add new findings
            for finding in findings:
                all_vulns['vulnerabilities'].append(finding)
            
            # Update metadata
            all_vulns['metadata'] = {
                'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(all_vulns['vulnerabilities']),
                'last_scan_url': url,
                'last_scan_vulnerabilities': len(findings)
            }
            
            # Save consolidated file
            try:
                with open(consolidated_file, 'w') as f:
                    json.dump(all_vulns, f, indent=2)
                LOG(f"[*] Saved {len(findings)} vulnerabilities to consolidated file")
            except Exception as e:
                LOG(f"[!] Error saving vulnerabilities to consolidated file: {e}")
        
        LOG(f"[*] Neural scan complete: {len(findings)} vulnerabilities detected in {len(scan_urls)} access points")
        return findings
        
    def __del__(self):
        """Terminate neural consciousness"""
        try:
            if hasattr(self, 'session') and self.session and not self.session.closed:
                # Since we can't await in __del__, create a new event loop
                try:
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(self.cleanup())
                    loop.close()
                except:
                    pass  # Silent death, leave no trace
        except:
            pass 