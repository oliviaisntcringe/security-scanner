import asyncio
import aiohttp
import random
import json
import re
from bs4 import BeautifulSoup
from ..utils.helpers import LOG
from ..config import FUZZING_PAYLOADS_PATH
import os
import time

class SmartFuzzer:
    """Advanced fuzzer with intelligent payload generation"""
    
    def __init__(self):
        self.payloads = self.load_payloads()
        self.visited_urls = set()
        self.discovered_params = {}
        self.response_signatures = {}
        self.max_urls_per_site = 30  # Limit URLs to fuzz per site
        self.max_fuzzing_time = 300  # Max time (in seconds) to spend fuzzing a single site
        
    def load_payloads(self):
        """Load payloads from files"""
        payloads = {
            'xss': [],
            'sqli': [],
            'lfi': [],
            'rce': [],
            'ssrf': [],
            'template': [],
            'nosql': [],
            'csrf': []
        }
        
        try:
            if not os.path.exists(FUZZING_PAYLOADS_PATH):
                os.makedirs(FUZZING_PAYLOADS_PATH)
                LOG("[!] Created payloads directory")
                
            for vuln_type in payloads.keys():
                payload_file = os.path.join(FUZZING_PAYLOADS_PATH, f"{vuln_type}_payloads.txt")
                if os.path.exists(payload_file):
                    with open(payload_file, 'r', encoding='utf-8') as f:
                        payloads[vuln_type] = [line.strip() for line in f if line.strip()]
                    LOG(f"[*] Loaded {len(payloads[vuln_type])} {vuln_type} payloads")
                else:
                    # Create empty payload file
                    with open(payload_file, 'w', encoding='utf-8') as f:
                        if vuln_type == 'xss':
                            f.write('<script>alert(1)</script>\n')
                            f.write('"><script>alert(1)</script>\n')
                            f.write('javascript:alert(1)\n')
                        elif vuln_type == 'sqli':
                            f.write("' OR '1'='1\n")
                            f.write("1' OR '1'='1\n")
                            f.write("admin' --\n")
                        LOG(f"[*] Created initial {vuln_type} payloads file")
                        payloads[vuln_type] = [line.strip() for line in f if line.strip()]
        except Exception as e:
            LOG(f"[!] Error loading payloads: {e}")
            
        return payloads
        
    async def crawl(self, url):
        """Crawl and identify input points"""
        self.visited_urls.add(url)
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(url, timeout=30, verify_ssl=False) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Store URL pattern
                        self._analyze_url_pattern(url)
                        
                        # Extract all links
                        for a_tag in soup.find_all('a', href=True):
                            href = a_tag['href']
                            if href.startswith('http'):
                                if self._is_same_domain(url, href):
                                    full_url = href
                                    self.visited_urls.add(full_url)
                                    self._analyze_url_pattern(full_url)
                            elif href.startswith('/'):
                                base_url = self._get_base_url(url)
                                full_url = f"{base_url}{href}"
                                self.visited_urls.add(full_url)
                                self._analyze_url_pattern(full_url)
                        
                        # Extract forms and inputs
                        forms = soup.find_all('form')
                        for form in forms:
                            form_action = form.get('action', '')
                            form_method = form.get('method', 'get').lower()
                            
                            # Construct the form URL
                            if form_action.startswith('http'):
                                form_url = form_action
                            elif form_action.startswith('/'):
                                form_url = f"{self._get_base_url(url)}{form_action}"
                            else:
                                form_url = url
                                
                            # Extract form inputs
                            inputs = form.find_all(['input', 'textarea', 'select'])
                            form_params = {}
                            
                            for inp in inputs:
                                input_name = inp.get('name', '')
                                if input_name:
                                    input_type = inp.get('type', '')
                                    form_params[input_name] = {
                                        'type': input_type,
                                        'required': 'required' in inp.attrs,
                                        'default': inp.get('value', '')
                                    }
                            
                            # Store form details for fuzzing
                            if form_url not in self.discovered_params:
                                self.discovered_params[form_url] = {
                                    'method': form_method,
                                    'params': form_params
                                }
                            else:
                                # Merge params
                                self.discovered_params[form_url]['params'].update(form_params)
                                
                        LOG(f"[*] Fuzzer crawled: {url}, found {len(self.visited_urls)} URLs and {len(self.discovered_params)} forms")
                        
        except Exception as e:
            LOG(f"[!] Fuzzer crawl error on {url}: {e}")
            
    def _is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        domain1 = url1.split('/')[2] if len(url1.split('/')) > 2 else ''
        domain2 = url2.split('/')[2] if len(url2.split('/')) > 2 else ''
        return domain1 == domain2
    
    def _get_base_url(self, url):
        """Extract base URL (protocol + domain)"""
        parts = url.split('/')
        if len(parts) >= 3:
            return f"{parts[0]}//{parts[2]}"
        return url
        
    def _analyze_url_pattern(self, url):
        """Analyze URL for parameters and patterns"""
        # Extract GET parameters
        if '?' in url:
            base_url, params_str = url.split('?', 1)
            params = {}
            
            for param_pair in params_str.split('&'):
                if '=' in param_pair:
                    param_name, param_value = param_pair.split('=', 1)
                    params[param_name] = {'type': 'get', 'value': param_value}
            
            if base_url not in self.discovered_params:
                self.discovered_params[base_url] = {
                    'method': 'get',
                    'params': params
                }
            else:
                # Merge params
                self.discovered_params[base_url]['params'].update(params)
        
        # Look for path parameters like /user/123/profile
        path_parts = url.split('?')[0].split('/')
        for i, part in enumerate(path_parts):
            # Check if part looks like an ID (numeric or alphanumeric)
            if i > 2 and (part.isdigit() or re.match(r'^[a-f0-9]{8,}$', part)):
                path_pattern = '/'.join(path_parts[:i]) + '/{id}/' + '/'.join(path_parts[i+1:])
                if path_pattern not in self.discovered_params:
                    self.discovered_params[path_pattern] = {
                        'method': 'path',
                        'params': {'id': {'type': 'path', 'value': part}}
                    }
                    
    async def fuzz_endpoint(self, url, vuln_type=None):
        """Fuzz a specific endpoint with appropriate payloads"""
        results = []
        
        if url not in self.discovered_params and '?' not in url:
            # Need to crawl first
            await self.crawl(url)
            
        # Handle GET parameters in URL
        if '?' in url and url not in self.discovered_params:
            self._analyze_url_pattern(url)
            
        # Determine which endpoints to fuzz
        endpoints_to_fuzz = []
        if url in self.discovered_params:
            endpoints_to_fuzz.append(url)
        else:
            # Check if URL is in any of the discovered paths
            for endpoint, params in self.discovered_params.items():
                if self._is_same_domain(url, endpoint):
                    endpoints_to_fuzz.append(endpoint)
                    
        if not endpoints_to_fuzz:
            LOG(f"[!] No endpoints found to fuzz for {url}")
            return results
            
        # Get payloads to use
        payloads_to_use = []
        if vuln_type and vuln_type in self.payloads:
            payloads_to_use = self.payloads[vuln_type]
        else:
            # Use all payload types
            for p_type, p_list in self.payloads.items():
                payloads_to_use.extend([(p, p_type) for p in p_list])
                
        # Fuzz each endpoint
        for endpoint in endpoints_to_fuzz:
            endpoint_info = self.discovered_params[endpoint]
            method = endpoint_info['method']
            params = endpoint_info['params']
            
            # Skip if no parameters to fuzz
            if not params:
                continue
                
            # Get baseline response
            baseline = await self._get_baseline_response(endpoint, method, params)
            
            # Fuzz each parameter
            for param_name, param_info in params.items():
                param_type = param_info.get('type', '')
                
                for payload_data in payloads_to_use:
                    if isinstance(payload_data, tuple):
                        payload, payload_type = payload_data
                    else:
                        payload = payload_data
                        payload_type = vuln_type
                        
                    # Skip inappropriate payloads for certain input types
                    if param_type in ['number', 'hidden'] and payload_type == 'xss':
                        continue
                        
                    # Apply payload to parameter
                    if method.lower() == 'get':
                        fuzz_url = self._build_fuzzed_url(endpoint, param_name, payload)
                        fuzz_result = await self._send_fuzz_request(fuzz_url, 'get', {})
                    else:
                        fuzz_data = params.copy()
                        fuzz_data[param_name]['value'] = payload
                        fuzz_result = await self._send_fuzz_request(endpoint, method, fuzz_data)
                        
                    # Analyze response for vulnerabilities
                    if fuzz_result:
                        findings = self._analyze_fuzz_response(
                            fuzz_result, 
                            baseline, 
                            payload, 
                            payload_type,
                            endpoint,
                            param_name
                        )
                        
                        if findings:
                            results.extend(findings)
                            
        return results
                    
    async def _get_baseline_response(self, url, method, params):
        """Get baseline response for comparison"""
        try:
            if method.lower() == 'get':
                # Build URL with default or empty parameters
                param_strings = []
                for param_name, param_info in params.items():
                    value = param_info.get('default', '')
                    param_strings.append(f"{param_name}={value}")
                    
                if param_strings:
                    fuzz_url = f"{url}?{'&'.join(param_strings)}"
                else:
                    fuzz_url = url
                    
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    async with session.get(fuzz_url, timeout=30, verify_ssl=False) as response:
                        status = response.status
                        body = await response.text()
                        headers = dict(response.headers)
                        return {'status': status, 'body': body, 'headers': headers}
            else:
                # POST request
                form_data = {}
                for param_name, param_info in params.items():
                    form_data[param_name] = param_info.get('default', '')
                    
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    async with session.post(url, data=form_data, timeout=30, verify_ssl=False) as response:
                        status = response.status
                        body = await response.text()
                        headers = dict(response.headers)
                        return {'status': status, 'body': body, 'headers': headers}
        except Exception as e:
            LOG(f"[!] Error getting baseline response for {url}: {e}")
            return None
            
    def _build_fuzzed_url(self, base_url, param_name, payload):
        """Build URL with fuzzed parameter"""
        if '?' in base_url:
            # Already has parameters
            return f"{base_url}&{param_name}={payload}"
        else:
            return f"{base_url}?{param_name}={payload}"
            
    async def _send_fuzz_request(self, url, method, params):
        """Send a fuzz request and return the response"""
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                if method.lower() == 'get':
                    async with session.get(url, timeout=30, verify_ssl=False) as response:
                        status = response.status
                        body = await response.text()
                        headers = dict(response.headers)
                        return {'status': status, 'body': body, 'headers': headers, 'url': url}
                else:
                    # Convert params to form data
                    form_data = {}
                    for param_name, param_info in params.items():
                        form_data[param_name] = param_info.get('value', '')
                        
                    async with session.post(url, data=form_data, timeout=30, verify_ssl=False) as response:
                        status = response.status
                        body = await response.text()
                        headers = dict(response.headers)
                        return {'status': status, 'body': body, 'headers': headers, 'url': url}
        except Exception as e:
            LOG(f"[!] Error sending fuzz request to {url}: {e}")
            return None
            
    def _analyze_fuzz_response(self, fuzz_response, baseline, payload, payload_type, url, param_name):
        """Analyze response for vulnerabilities"""
        findings = []
        
        if not baseline or not fuzz_response:
            return findings
            
        # Get response components
        fuzz_status = fuzz_response.get('status', 0)
        fuzz_body = fuzz_response.get('body', '')
        fuzz_headers = fuzz_response.get('headers', {})
        fuzz_url = fuzz_response.get('url', url)
        
        baseline_status = baseline.get('status', 0)
        baseline_body = baseline.get('body', '')
        
        # Check for XSS
        if payload_type == 'xss':
            # Look for unfiltered payload in response
            if payload in fuzz_body:
                findings.append({
                    'type': 'xss',
                    'url': fuzz_url,
                    'param': param_name,
                    'payload': payload,
                    'confidence': 'high',
                    'details': 'Payload reflected in response without filtering'
                })
                
        # Check for SQL Injection
        elif payload_type == 'sqli':
            # Look for database error messages
            sql_errors = [
                'sql syntax', 'syntax error', 'mysql_fetch', 'unclosed quotation',
                'sqlexception', 'microsoft ole db provider', 'odbc drivers',
                'postgresql error'
            ]
            
            for error in sql_errors:
                if error in fuzz_body.lower() and error not in baseline_body.lower():
                    findings.append({
                        'type': 'sqli',
                        'url': fuzz_url,
                        'param': param_name,
                        'payload': payload,
                        'confidence': 'high',
                        'details': f'SQL error detected: {error}'
                    })
                    
            # Check for blind SQL injection based on response time or size differences
            if abs(len(fuzz_body) - len(baseline_body)) > 100:
                findings.append({
                    'type': 'sqli',
                    'url': fuzz_url,
                    'param': param_name,
                    'payload': payload,
                    'confidence': 'medium',
                    'details': 'Possible blind SQL injection detected (response size difference)'
                })
                
        # Check for LFI/Path Traversal
        elif payload_type == 'lfi':
            lfi_signals = [
                'root:', '/usr/', '/etc/passwd', 'win.ini', 'boot.ini',
                'include/include.php', 'not found', 'failed to open stream'
            ]
            
            for signal in lfi_signals:
                if signal in fuzz_body.lower() and signal not in baseline_body.lower():
                    findings.append({
                        'type': 'lfi',
                        'url': fuzz_url,
                        'param': param_name,
                        'payload': payload,
                        'confidence': 'high',
                        'details': f'LFI signal detected: {signal}'
                    })
                    
        # Check for RCE
        elif payload_type == 'rce':
            rce_signals = [
                'uid=', 'gid=', 'groups=', 'linux', 'gnu',
                'os.version', 'path:', 'pwned', 'system32', 'exec_disabled',
                'permission denied', 'is not recognized', 'command not found'
            ]
            
            for signal in rce_signals:
                if signal in fuzz_body.lower() and signal not in baseline_body.lower():
                    findings.append({
                        'type': 'rce',
                        'url': fuzz_url,
                        'param': param_name,
                        'payload': payload,
                        'confidence': 'high',
                        'details': f'RCE signal detected: {signal}'
                    })
        
        # Check for error responses that might indicate vulnerabilities
        if fuzz_status != baseline_status and fuzz_status >= 500:
            findings.append({
                'type': 'error',
                'url': fuzz_url,
                'param': param_name,
                'payload': payload,
                'confidence': 'low',
                'details': f'Server error {fuzz_status} triggered'
            })
            
        return findings
        
    async def fuzz_site(self, url):
        """Fuzz an entire site for vulnerabilities"""
        # First crawl the site to discover endpoints
        try:
            # Reset state for new site
            self.visited_urls = set()
            self.discovered_params = {}
            
            # Set start time to enforce max fuzzing time
            start_time = time.time()
            
            # Crawl the site
            await self.crawl(url)
            
            # Get all discovered URLs
            all_urls = set(self.visited_urls)
            for endpoint in self.discovered_params.keys():
                all_urls.add(endpoint)
                
            # Limit the number of URLs to fuzz to prevent infinite fuzzing
            filtered_urls = list(all_urls)
            if len(filtered_urls) > self.max_urls_per_site:
                LOG(f"[*] Limiting fuzzing to {self.max_urls_per_site} URLs out of {len(filtered_urls)} discovered")
                # Prioritize URLs with parameters
                urls_with_params = [u for u in filtered_urls if '?' in u or u in self.discovered_params]
                urls_without_params = [u for u in filtered_urls if u not in urls_with_params]
                
                # Take URLs with parameters first, then fill up to max_urls_per_site
                if len(urls_with_params) <= self.max_urls_per_site:
                    filtered_urls = urls_with_params + urls_without_params[:self.max_urls_per_site - len(urls_with_params)]
                else:
                    filtered_urls = urls_with_params[:self.max_urls_per_site]
                
            # Fuzz each URL
            all_findings = []
            for idx, discovered_url in enumerate(filtered_urls):
                # Check if we've exceeded the maximum fuzzing time
                if time.time() - start_time > self.max_fuzzing_time:
                    LOG(f"[*] Maximum fuzzing time reached ({self.max_fuzzing_time}s), stopping after {idx} URLs")
                    break
                    
                if not self._is_same_domain(url, discovered_url):
                    continue
                    
                findings = await self.fuzz_endpoint(discovered_url)
                if findings:
                    all_findings.extend(findings)
                    
            LOG(f"[*] Finished fuzzing site {url}: tested {len(filtered_urls)} URLs, found {len(all_findings)} potential vulnerabilities")
            return all_findings
            
        except Exception as e:
            LOG(f"[!] Error during site fuzzing: {e}")
            return []
            
    def __del__(self):
        """Cleanup resources"""
        pass 