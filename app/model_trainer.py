import os
import json
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import re
from bs4 import BeautifulSoup
import asyncio
import aiohttp
from .utils.helpers import LOG
from .config import ML_MODELS_PATH, RESULTS_DIR

class VulnerabilityModelTrainer:
    """Trains machine learning models to detect vulnerabilities"""
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.training_data = {
            'xss': {'features': [], 'labels': []},
            'sqli': {'features': [], 'labels': []},
            'csrf': {'features': [], 'labels': []},
            'lfi': {'features': [], 'labels': []},
            'rce': {'features': [], 'labels': []},
            'ssrf': {'features': [], 'labels': []},
        }
        self.feature_names = {}
        
    async def load_training_data_from_results(self):
        """Load training data from previous scan results"""
        if not os.path.exists(RESULTS_DIR):
            LOG("[!] Results directory not found")
            return False
            
        result_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.json')]
        if not result_files:
            LOG("[!] No result files found")
            return False
            
        LOG(f"[*] Found {len(result_files)} result files for training")
        
        # Load and process each result file
        for filename in result_files:
            filepath = os.path.join(RESULTS_DIR, filename)
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    scan_result = json.load(f)
                    
                if 'vulnerabilities' not in scan_result or not scan_result['vulnerabilities']:
                    continue
                    
                base_url = scan_result.get('url', '')
                if not base_url:
                    continue
                    
                # Extract vulnerable and non-vulnerable URLs
                for vuln in scan_result['vulnerabilities']:
                    vuln_type = vuln.get('type', '')
                    vuln_url = vuln.get('url', '')
                    
                    if not vuln_type or not vuln_url or vuln_type not in self.training_data:
                        continue
                        
                    # Add to positive samples
                    await self._extract_and_add_features(vuln_url, vuln_type, True)
                    
                    # Find some non-vulnerable samples from same domain
                    if 'visited_urls' in scan_result:
                        non_vuln_urls = []
                        for url in scan_result['visited_urls']:
                            # Same domain but not the vulnerable URL
                            if self._is_same_domain(url, base_url) and url != vuln_url:
                                non_vuln_urls.append(url)
                                
                        # Select a few non-vulnerable samples
                        for url in non_vuln_urls[:3]:  # Limit to 3 negative samples per positive
                            await self._extract_and_add_features(url, vuln_type, False)
                    
            except Exception as e:
                LOG(f"[!] Error processing result file {filename}: {e}")
                
        # Report on training data collected
        for vuln_type, data in self.training_data.items():
            pos_samples = sum(data['labels'])
            total_samples = len(data['labels'])
            LOG(f"[*] {vuln_type}: {pos_samples} positive and {total_samples-pos_samples} negative samples")
            
        return True
        
    async def load_training_data_from_file(self, filepath):
        """Load training data from a prepared JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Expect format: {vuln_type: [{url, html, is_vulnerable}, ...]}
            for vuln_type, samples in data.items():
                if vuln_type not in self.training_data:
                    LOG(f"[!] Skipping unknown vulnerability type: {vuln_type}")
                    continue
                    
                for sample in samples:
                    url = sample.get('url', '')
                    html = sample.get('html', '')
                    is_vulnerable = sample.get('is_vulnerable', False)
                    
                    if not url or not html:
                        continue
                        
                    # Extract features and add to training data
                    features = self._extract_features_from_html(url, html, vuln_type)
                    self.training_data[vuln_type]['features'].append(features)
                    self.training_data[vuln_type]['labels'].append(1 if is_vulnerable else 0)
                    
            LOG(f"[*] Loaded training data from {filepath}")
            return True
            
        except Exception as e:
            LOG(f"[!] Error loading training data from file: {e}")
            return False
            
    async def _extract_and_add_features(self, url, vuln_type, is_vulnerable):
        """Fetch URL and extract features for training"""
        try:
            # Fetch URL content
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.get(url, timeout=30, verify_ssl=False) as response:
                    if response.status != 200:
                        return
                        
                    html = await response.text()
                    
            # Extract features
            features = self._extract_features_from_html(url, html, vuln_type)
            
            # Add to training data
            self.training_data[vuln_type]['features'].append(features)
            self.training_data[vuln_type]['labels'].append(1 if is_vulnerable else 0)
            
        except Exception as e:
            LOG(f"[!] Error extracting features from {url}: {e}")
            
    def _extract_features_from_html(self, url, html, vuln_type):
        """Extract relevant features from HTML based on vulnerability type"""
        features = {}
        
        # Common features
        features['url_length'] = len(url)
        features['has_query_params'] = 1 if '?' in url else 0
        features['num_params'] = len(url.split('?')[1].split('&')) if '?' in url else 0
        features['html_length'] = len(html)
        
        # Extract URL parameter names and values for advanced analysis
        param_values = []
        if '?' in url:
            query_string = url.split('?', 1)[1]
            for param in query_string.split('&'):
                if '=' in param:
                    name, value = param.split('=', 1)
                    param_values.append(value)
        features['param_values_length'] = sum(len(v) for v in param_values) / max(1, len(param_values)) if param_values else 0
        features['max_param_length'] = max([len(v) for v in param_values]) if param_values else 0
        
        # Advanced URL analysis
        features['has_encoded_chars'] = 1 if '%' in url else 0
        features['num_encoded_chars'] = url.count('%')
        features['has_hex_chars'] = 1 if re.search(r'\\x[0-9a-f]{2}', url.lower()) else 0
        features['has_unicode_chars'] = 1 if re.search(r'\\u[0-9a-f]{4}', url.lower()) else 0
        features['has_base64_pattern'] = 1 if re.search(r'[a-zA-Z0-9+/]{4,}={0,2}', url) else 0
        
        # Parse HTML with BeautifulSoup
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            # Common DOM elements
            features['num_forms'] = len(soup.find_all('form'))
            features['num_inputs'] = len(soup.find_all('input'))
            features['num_scripts'] = len(soup.find_all('script'))
            features['num_iframes'] = len(soup.find_all('iframe'))
            features['num_links'] = len(soup.find_all('a'))
            
            # Advanced DOM analysis
            features['num_event_handlers'] = sum(1 for tag in soup.find_all() for attr in tag.attrs if attr.startswith('on'))
            features['num_inline_scripts'] = len([s for s in soup.find_all('script') if s.string])
            features['num_external_scripts'] = len([s for s in soup.find_all('script') if s.get('src')])
            features['num_data_uris'] = sum(1 for tag in soup.find_all() for attr, val in tag.attrs.items() if isinstance(val, str) and val.startswith('data:'))
            features['num_suspicious_comments'] = len(re.findall(r'<!--.*?(password|admin|config|db|key|secret|token).*?-->', html, re.I))
            
            # Extract text for text analysis
            text = soup.get_text()
            features['text_length'] = len(text)
            
            # Specific features by vulnerability type
            if vuln_type == 'xss':
                features['has_onload'] = 1 if 'onload=' in html.lower() else 0
                features['has_onerror'] = 1 if 'onerror=' in html.lower() else 0
                features['has_onclick'] = 1 if 'onclick=' in html.lower() else 0
                features['has_eval'] = 1 if 'eval(' in html.lower() else 0
                features['has_document_write'] = 1 if 'document.write' in html.lower() else 0
                features['has_alert'] = 1 if 'alert(' in html.lower() else 0
                features['encoded_chars'] = len(re.findall(r'&#\d+;', html))
                # Advanced XSS features
                features['has_atob_btoa'] = 1 if re.search(r'(atob|btoa)\(', html.lower()) else 0
                features['has_fromcharcode'] = 1 if 'fromcharcode' in html.lower() else 0
                features['has_innerhtml'] = 1 if 'innerhtml' in html.lower() else 0
                features['has_eventlistener'] = 1 if 'addeventlistener' in html.lower() else 0
                features['has_svg_tags'] = 1 if '<svg' in html.lower() else 0
                features['has_script_protocol'] = 1 if 'javascript:' in html.lower() else 0
                features['has_vbscript_protocol'] = 1 if 'vbscript:' in html.lower() else 0
                features['has_data_protocol'] = 1 if 'data:' in html.lower() else 0
                features['has_entities'] = 1 if re.search(r'&[#a-zA-Z0-9]+;', html) else 0
                features['has_template_tag'] = 1 if '<template' in html.lower() else 0
                features['has_css_expression'] = 1 if 'expression(' in html.lower() else 0
                
            elif vuln_type == 'sqli':
                features['has_sql_keywords'] = sum(1 for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'FROM', 'WHERE',
                                                            'UNION', 'JOIN', 'HAVING', 'GROUP', 'ORDER', 'EXEC', 
                                                            'TRUNCATE', 'DROP', 'CREATE', 'ALTER', 'LIMIT', 'OFFSET'] 
                                                if kw in html.upper())
                features['has_sql_errors'] = sum(1 for err in ['sql syntax', 'mysql error', 'database error', 'ora-', 
                                                          'syntax error', 'incorrect syntax', 'unexpected token',
                                                          'unterminated string', 'warning: mysql', 'unclosed quotation',
                                                          'pg_query()', 'postgresql error', 'JDBC Error', 'ODBC SQL Server Driver', 'SQLite.Exception', 'System.Data.SQLite.SQLiteException']
                                               if err in html.lower())
                features['has_id_param'] = 1 if re.search(r'[?&]id=', url.lower()) else 0
                features['has_number_param'] = len(re.findall(r'[?&][a-z]+=[0-9]+', url.lower()))
                features['has_comment_marker'] = 1 if re.search(r'(--|#|/\*)', url) else 0
                features['has_sleep_benchmark'] = 1 if re.search(r'(sleep|benchmark|pg_sleep|waitfor\s+delay)', url.lower()) else 0
                features['has_blind_sqli_patterns'] = 1 if re.search(r'(and\s+\d+=\d+|or\s+\d+=\d+)', url.lower()) else 0
                features['has_quote_truncation'] = 1 if "'" in url or '"' in url else 0
                features['has_sqli_concat'] = 1 if re.search(r'(concat\(|concat_ws\(|group_concat\()', url.lower()) else 0
                features['has_information_schema'] = 1 if 'information_schema' in url.lower() else 0
                features['has_system_tables'] = 1 if re.search(r'(sys\.tables|sys\.objects|all_tables|user_tables)', url.lower()) else 0
                features['has_case_when'] = 1 if re.search(r'(case\s+when|decode\()', url.lower()) else 0
                features['has_union_select'] = 1 if 'union select' in html.lower() else 0
                features['has_order_by'] = 1 if 'order by' in html.lower() else 0
                features['has_group_by'] = 1 if 'group by' in html.lower() else 0
                features['has_having'] = 1 if 'having' in html.lower() else 0
                features['has_limit'] = 1 if 'limit' in html.lower() else 0
                features['has_stack_query'] = 1 if ';' in url else 0
                features['has_encoded_payload'] = 1 if re.search(r'%27|%23|%2F\*', url.lower()) else 0
                features['has_suspicious_cookie'] = 1 if 'cookie' in html.lower() and re.search(r'1=1|or|and', html.lower()) else 0
                features['has_suspicious_header'] = 1 if 'user-agent' in html.lower() and re.search(r'1=1|or|and', html.lower()) else 0
                features['has_json_error'] = 1 if re.search(r'json.*error', html.lower()) else 0
                features['response_length'] = len(html)
                features['response_code_200'] = 1 if '200 OK' in html else 0
                features['response_code_500'] = 1 if '500 Internal Server Error' in html else 0
                features['response_code_403'] = 1 if '403 Forbidden' in html else 0
                features['has_waf_sign'] = 1 if re.search(r'waf|firewall|blocked|captcha', html.lower()) else 0
                features['has_payload_in_form'] = 1 if any('id=' in (f.get('action') or '') for f in soup.find_all('form')) else 0
                features['has_payload_in_script'] = 1 if any('id=' in (s.string or '') for s in soup.find_all('script')) else 0
                features['has_payload_in_link'] = 1 if any('id=' in (a.get('href') or '') for a in soup.find_all('a')) else 0
                features['has_payload_in_header'] = 1 if 'id=' in html.lower() and 'header' in html.lower() else 0
                features['has_payload_in_cookie'] = 1 if 'id=' in html.lower() and 'cookie' in html.lower() else 0
                
            elif vuln_type == 'csrf':
                features['has_csrf_token'] = 1 if 'csrf' in html.lower() else 0
                features['has_hidden_inputs'] = len(soup.find_all('input', {'type': 'hidden'}))
                features['has_post_form'] = len(soup.find_all('form', {'method': 'post'}))
                features['has_state_param'] = 1 if 'state=' in url else 0
                # Advanced CSRF features
                features['has_form_with_action'] = len([f for f in soup.find_all('form') if f.get('action')])
                features['has_form_no_token'] = len([f for f in soup.find_all('form', {'method': 'post'}) 
                                                  if not any('csrf' in i.get('name', '').lower() for i in f.find_all('input'))])
                features['has_ajax_call'] = 1 if re.search(r'(XMLHttpRequest|fetch\(|ajax\()', html.lower()) else 0
                features['has_json_body'] = 1 if re.search(r'application/json', html.lower()) else 0
                features['has_sensitive_actions'] = sum(1 for action in ['transfer', 'delete', 'create', 'update', 'change', 
                                                                       'password', 'account', 'profile', 'upload']
                                                     if action in html.lower())
                features['has_same_origin_meta'] = 1 if 'X-Frame-Options' in html or 'Content-Security-Policy' in html else 0
                
            elif vuln_type == 'lfi':
                features['has_path_param'] = 1 if re.search(r'[?&](path|file|include|require|load|src|filepath|template|theme|page|document)=', url.lower()) else 0
                features['has_dotdot'] = 1 if '../' in url else 0
                features['has_file_indicators'] = sum(1 for ind in ['etc/passwd', 'win.ini', 'boot.ini', 'php://', 'file://', 'c:\\', 'windows\\']
                                                   if ind in html.lower() or ind in url.lower())
                features['has_include_keywords'] = sum(1 for kw in ['include', 'require', 'include_once', 'file(', 'readfile(', 'fopen(']
                                                    if kw in html.lower())
                # Advanced LFI features
                features['has_path_traversal'] = 1 if re.search(r'(\.\.\/|\.\.\\|%2e%2e%2f|%252e%252e%252f)', url) else 0
                features['has_php_wrapper'] = 1 if re.search(r'php://(filter|input|data|zip|compress\.|phar://)', url.lower()) else 0
                features['has_filter_convert'] = 1 if 'convert.' in url.lower() else 0
                features['has_log_poisoning'] = 1 if re.search(r'(access_log|error_log|logs?\/)', url.lower()) else 0
                features['has_proc_self'] = 1 if re.search(r'proc\/self\/', url.lower()) else 0
                features['has_null_byte'] = 1 if re.search(r'%00|\x00', url) else 0
                features['has_double_encoding'] = 1 if re.search(r'%25[0-9a-f]{2}', url.lower()) else 0
                features['has_base64_padding'] = 1 if re.search(r'={1,2}$', ''.join(param_values)) else 0
                
            elif vuln_type in ['rce', 'ssrf']:
                features['has_suspicious_funcs'] = sum(1 for f in ['system', 'exec', 'shell_exec', 'eval', 'curl', 'wget',
                                                                'passthru', 'proc_open', 'popen', 'bash', 'sh', 'cmd']
                                                    if f in html.lower())
                features['has_url_param'] = 1 if re.search(r'[?&](url|site|path|callback|webhook|dest|redirect|uri|fetch|load)=', url.lower()) else 0
                features['has_cmd_param'] = 1 if re.search(r'[?&](cmd|command|exec|execute|query|code|payload|run)=', url.lower()) else 0
                features['has_http_in_params'] = 1 if re.search(r'[?&][^=]+=https?://', url.lower()) else 0
                
                if vuln_type == 'rce':
                    # Additional RCE features
                    features['has_os_commands'] = 1 if re.search(r'(ping|nc|netcat|wget|curl|bash|sh|powershell|cmd\.exe|nslookup|whoami|cat |ls |dir |pwd )', url.lower()) else 0
                    features['has_special_chars'] = sum(1 for c in ['&', '|', ';', '$', '`', '>', '<'] if c in url)
                    features['has_backticks'] = 1 if '`' in url else 0
                    features['has_base64_cmd'] = 1 if re.search(r'base64[^;]*;|base64 -d|base64 --decode', url.lower()) else 0
                    features['has_hex_encoding'] = 1 if re.search(r'\\x[0-9a-f]{2}', url.lower()) else 0
                    features['has_chmod'] = 1 if 'chmod' in url.lower() else 0
                    features['has_stdin_redirect'] = 1 if '<<<' in url else 0
                    features['has_env_variables'] = 1 if re.search(r'\$[A-Za-z0-9_]+|\${[^}]+}', url) else 0
                    features['has_brace_expansion'] = 1 if re.search(r'{[^}]+,[^}]+}', url) else 0
                    features['has_file_redirection'] = 1 if re.search(r'>\s*\w+|\d+>\s*\w+', url) else 0
                    features['has_reverse_shell'] = 1 if re.search(r'\/dev\/tcp\/|bash -i|python -c|perl -e|nc -e', url.lower()) else 0
                    
                    # Language-specific RCE patterns
                    # PHP-specific
                    features['has_php_rce_funcs'] = 1 if re.search(r'(system\s*\(|shell_exec\s*\(|exec\s*\(|passthru\s*\(|popen\s*\(|proc_open\s*\(|pcntl_exec\s*\()', url.lower() + html.lower()) else 0
                    features['has_php_eval'] = 1 if re.search(r'(eval\s*\(|assert\s*\(|create_function\s*\()', url.lower() + html.lower()) else 0
                    features['has_php_include'] = 1 if re.search(r'(include\s*\(|include_once\s*\(|require\s*\(|require_once\s*\()', url.lower() + html.lower()) else 0
                    
                    # Python-specific
                    features['has_python_os_rce'] = 1 if re.search(r'(__import__\s*\(\s*[\'"]os[\'"]\)|os\.(system|popen|exec|spawn)|subprocess\.(call|Popen|run))', url.lower() + html.lower()) else 0
                    features['has_python_eval'] = 1 if re.search(r'(eval\s*\(|exec\s*\(|compile\s*\()', url.lower() + html.lower()) else 0
                    features['has_python_builtins'] = 1 if re.search(r'(__builtins__|globals\(\)|locals\(\)|getattr\s*\()', url.lower() + html.lower()) else 0
                    
                    # Node.js-specific
                    features['has_nodejs_rce'] = 1 if re.search(r'(require\s*\(\s*[\'"]child_process[\'"]\)|spawn\s*\(|exec\s*\(|execSync\s*\(|spawnSync\s*\()', url.lower() + html.lower()) else 0
                    features['has_nodejs_eval'] = 1 if re.search(r'(eval\s*\(|Function\s*\(|new Function\s*\(|vm\.runIn|process\.)', url.lower() + html.lower()) else 0
                    features['has_nodejs_module'] = 1 if re.search(r'(require\s*\(|module\.exports|__dirname|process\.mainModule)', url.lower() + html.lower()) else 0
                    
                    # Java-specific
                    features['has_java_rce'] = 1 if re.search(r'(Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder|getRuntime\(\))', url.lower() + html.lower()) else 0
                    features['has_java_spel'] = 1 if re.search(r'(T\(java\.lang\.Runtime\)|new java\.util\.Scanner|new java\.lang\.ProcessBuilder)', url.lower() + html.lower()) else 0
                    features['has_java_reflection'] = 1 if re.search(r'(\.getClass\(\)|\.forName\(|\.getMethod\(|\.invoke\()', url.lower() + html.lower()) else 0
                    
                    # Ruby-specific
                    features['has_ruby_rce'] = 1 if re.search(r'(`.*`|\%x\{|\%x\(|system\s*\(|exec\s*\(|spawn\s*\(|Kernel\.)', url.lower() + html.lower()) else 0
                    features['has_ruby_eval'] = 1 if re.search(r'(eval\s*\(|class_eval\s*\(|instance_eval\s*\()', url.lower() + html.lower()) else 0
                    features['has_ruby_io'] = 1 if re.search(r'(IO\.popen\(|Open3\.popen|IO\.read\()', url.lower() + html.lower()) else 0
                    
                    # Command separators and WAF bypasses
                    features['has_cmd_separators'] = 1 if re.search(r'(;|\$\(|\|\||&&|`|\|)', url) else 0
                    features['has_ifs_bypass'] = 1 if re.search(r'\$\{IFS\}', url) else 0
                    features['has_space_bypass'] = 1 if re.search(r'(\$\{IFS\}|%09|\+|%20|%0a|%0d|\t)', url) else 0
                    features['has_quotes_bypass'] = 1 if re.search(r"('\\''|\"\\\"\"|\\'|\\\"|\\\\)", url) else 0
                    features['has_char_obfuscation'] = 1 if re.search(r"(\${[a-zA-Z0-9_]+:0:1}|\$[a-zA-Z0-9_]+\[0\]|\\[0-9]+|\\x[0-9a-f]{2})", url.lower()) else 0
                    
                    # Templating and deserialization
                    features['has_template_injection'] = 1 if re.search(r'(\{\{.*\}\}|\{\%.*\%\}|\$\{.*\}|<\?.*\?>)', url) else 0
                    features['has_deserialization'] = 1 if re.search(r'(O:[0-9]+:|rO0|objectClass=|java:comp/env|javax\.naming|jndi:|ldap:|rmi:)', url.lower() + html.lower()) else 0
                    
                    # Common output patterns in RCE responses
                    features['has_passwd_output'] = 1 if re.search(r'(root:x:0:0:|[a-zA-Z0-9_-]+:[^:]+:[0-9]+:[0-9]+:)', html.lower()) else 0
                    features['has_uid_output'] = 1 if re.search(r'(uid=[0-9]+\([a-z0-9_-]+\)|gid=[0-9]+\([a-z0-9_-]+\))', html.lower()) else 0
                    features['has_directory_listing'] = 1 if re.search(r'(total\s+[0-9]+\s*\n.*drwx|rwxr-xr-x|ls: cannot access)', html.lower()) else 0
                    features['has_command_success'] = 1 if re.search(r'(command executed successfully|process started|execution completed)', html.lower()) else 0
                    
                    # Sophisticated features
                    features['has_rce_param_with_cmd'] = 1 if features['has_cmd_param'] == 1 and features['has_os_commands'] == 1 else 0
                    features['has_special_chars_with_cmd'] = 1 if features['has_special_chars'] > 0 and (features['has_os_commands'] == 1 or features['has_suspicious_funcs'] > 0) else 0
                    features['has_lang_specific_rce'] = max([
                        features.get('has_php_rce_funcs', 0),
                        features.get('has_python_os_rce', 0),
                        features.get('has_nodejs_rce', 0),
                        features.get('has_java_rce', 0),
                        features.get('has_ruby_rce', 0)
                    ])
                
                if vuln_type == 'ssrf':
                    features['has_url_param'] = 1 if re.search(r'[?&](url|site|path|callback|webhook|dest|redirect|uri|fetch|load|resource|domain|host|website|feed|to|out|image|link|proxy|forward|remote|open)=', url.lower()) else 0
                    features['num_params'] = len(url.split('?')[1].split('&')) if '?' in url else 0
                    features['has_post_body_url'] = 1 if re.search(r'url=', html.lower()) else 0
                    features['has_gopher_protocol'] = 1 if 'gopher://' in url.lower() else 0
                    features['has_dict_protocol'] = 1 if 'dict://' in url.lower() else 0
                    features['has_smb_protocol'] = 1 if 'smb://' in url.lower() else 0
                    features['has_ldap_protocol'] = 1 if 'ldap://' in url.lower() else 0
                    features['has_file_protocol'] = 1 if 'file://' in url.lower() else 0
                    features['has_php_protocol'] = 1 if 'php://' in url.lower() else 0
                    features['has_cloud_metadata'] = 1 if re.search(r'169.254.169.254|metadata.google.internal|metadata.azure.com|100.100.100.200', url.lower()) else 0
                    features['has_localhost'] = 1 if re.search(r'localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|localhost.localdomain', url.lower()) else 0
                    features['has_internal_ip'] = 1 if re.search(r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.', url) else 0
                    features['has_hex_ip'] = 1 if re.search(r'0x[a-f0-9]{8}', url.lower()) else 0
                    features['has_decimal_ip'] = 1 if re.search(r'\d{8,10}', url) else 0
                    features['has_ipv6_evasion'] = 1 if '[' in url and ']' in url else 0
                    features['has_at_in_url'] = 1 if '@' in url else 0
                    features['has_dns_rebinding'] = 1 if re.search(r'rebind|dynamic\.dns', url.lower()) else 0
                    features['has_x_forwarded_for'] = 1 if 'x-forwarded-for' in html.lower() else 0
                    features['has_host_header'] = 1 if 'host:' in html.lower() else 0
                    features['has_location_header'] = 1 if 'location:' in html.lower() else 0
                    features['has_ssrf_chain'] = 1 if html.lower().count('redirect') > 1 else 0
                    features['has_error_connection'] = 1 if re.search(r'connection refused|timeout|no route to host|invalid url|refused to connect', html.lower()) else 0
                    features['has_cloud_metadata_in_response'] = 1 if re.search(r'ami-id|instance-id|hostname|access-key', html.lower()) else 0
                    features['has_internal_ip_in_response'] = 1 if re.search(r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|localhost|127\.0\.0\.1', html.lower()) else 0
                    features['has_unexpected_redirect'] = 1 if 'location:' in html.lower() else 0
                    features['response_time'] = 0  # Можно добавить при интеграции с реальным запросом
                    features['response_length'] = len(html)
                    features['num_redirects'] = html.lower().count('location:')
                    features['has_payload_in_form'] = 1 if any('url=' in (f.get('action') or '') for f in soup.find_all('form')) else 0
                    features['has_payload_in_script'] = 1 if any('url=' in (s.string or '') for s in soup.find_all('script')) else 0
                    features['has_payload_in_link'] = 1 if any('url=' in (a.get('href') or '') for a in soup.find_all('a')) else 0
                    features['has_payload_in_header'] = 1 if 'url=' in html.lower() and 'header' in html.lower() else 0
                    features['has_payload_in_cookie'] = 1 if 'url=' in html.lower() and 'cookie' in html.lower() else 0
                
        except Exception as e:
            LOG(f"[!] Error extracting features: {e}")
            
        return features
        
    def _prepare_feature_vectors(self, vuln_type):
        """Convert feature dictionaries to vectors for ML"""
        raw_features = self.training_data[vuln_type]['features']
        if not raw_features:
            return None, None
            
        # Get all feature names
        feature_names = set()
        for feature_dict in raw_features:
            feature_names.update(feature_dict.keys())
            
        # Sort feature names for consistency
        feature_names = sorted(list(feature_names))
        self.feature_names[vuln_type] = feature_names
        
        # Create feature vectors
        X = []
        for feature_dict in raw_features:
            feature_vector = [feature_dict.get(name, 0) for name in feature_names]
            X.append(feature_vector)
            
        # Convert to numpy array
        X = np.array(X)
        y = np.array(self.training_data[vuln_type]['labels'])
        
        return X, y
        
    def train_models(self):
        """Train ML models for each vulnerability type"""
        for vuln_type in self.training_data.keys():
            LOG(f"[*] Training model for {vuln_type}")
            
            # Prepare data
            X, y = self._prepare_feature_vectors(vuln_type)
            if X is None or len(X) < 10:
                LOG(f"[!] Not enough data for {vuln_type}, skipping")
                continue
                
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)
            self.scalers[vuln_type] = scaler
            
            # Train model
            model = RandomForestClassifier(n_estimators=100, random_state=42)
            model.fit(X_train_scaled, y_train)
            self.models[vuln_type] = model
            
            # Evaluate model
            train_score = model.score(X_train_scaled, y_train)
            test_score = model.score(X_test_scaled, y_test)
            LOG(f"[*] {vuln_type} model - Train accuracy: {train_score:.4f}, Test accuracy: {test_score:.4f}")
            
            # Feature importance
            if hasattr(model, 'feature_importances_'):
                importances = model.feature_importances_
                indices = np.argsort(importances)[::-1]
                top_features = [(self.feature_names[vuln_type][i], importances[i]) for i in indices[:5]]
                LOG(f"[*] Top 5 features for {vuln_type}: {top_features}")
                
    def save_models(self):
        """Save trained models to disk"""
        LOG(f"[*] Saving models to {ML_MODELS_PATH}")
        LOG(f"[*] Models to save: {list(self.models.keys())}")
        
        if not os.path.exists(ML_MODELS_PATH):
            LOG(f"[*] Creating directory {ML_MODELS_PATH}")
            os.makedirs(ML_MODELS_PATH)
            
        for vuln_type, model in self.models.items():
            model_path = os.path.join(ML_MODELS_PATH, f"{vuln_type}_model.pkl")
            features_path = os.path.join(ML_MODELS_PATH, f"{vuln_type}_features.pkl")
            scaler_path = os.path.join(ML_MODELS_PATH, f"{vuln_type}_scaler.pkl")
            
            # Save model
            LOG(f"[*] Saving {vuln_type} model to {model_path}")
            with open(model_path, 'wb') as f:
                pickle.dump(model, f)
                
            # Save feature names
            with open(features_path, 'wb') as f:
                pickle.dump(self.feature_names[vuln_type], f)
                
            # Save scaler
            if vuln_type in self.scalers:
                with open(scaler_path, 'wb') as f:
                    pickle.dump(self.scalers[vuln_type], f)
                    
            LOG(f"[*] Saved {vuln_type} model to {model_path}")
            
    def _is_same_domain(self, url1, url2):
        """Check if two URLs belong to the same domain"""
        try:
            domain1 = url1.split('/')[2] if len(url1.split('/')) > 2 else ''
            domain2 = url2.split('/')[2] if len(url2.split('/')) > 2 else ''
            return domain1 == domain2
        except:
            return False

async def train_models():
    """Train and save ML models"""
    trainer = VulnerabilityModelTrainer()
    
    # Try to load training data from results
    result_data = await trainer.load_training_data_from_results()
    
    # If not enough data, try to load from supplementary file
    if not result_data or sum(len(data['labels']) for data in trainer.training_data.values()) < 100:
        data_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'training_data.json')
        if os.path.exists(data_path):
            await trainer.load_training_data_from_file(data_path)
    
    # Train models
    trainer.train_models()
    
    # Save models
    trainer.save_models()
    
if __name__ == "__main__":
    asyncio.run(train_models()) 