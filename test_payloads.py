#!/usr/bin/env python3
import os
import json
from app.config import FUZZING_PAYLOADS_PATH, EXPLOITS_PATH

def test_payload_loading():
    """Test loading payloads from files"""
    payload_types = [
        'xss', 'sqli', 'lfi', 'rce', 'ssrf', 'template', 'nosql', 'csrf'
    ]
    
    print("\n=== Testing Payloads ===")
    for vuln_type in payload_types:
        payload_file = os.path.join(FUZZING_PAYLOADS_PATH, f"{vuln_type}_payloads.txt")
        if os.path.exists(payload_file):
            with open(payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.strip() for line in f if line.strip()]
            print(f"[*] Loaded {len(payloads)} {vuln_type} payloads")
        else:
            print(f"[!] No payload file found for {vuln_type}")

def test_exploit_loading():
    """Test loading exploit templates"""
    template_types = [
        'xss', 'sqli', 'lfi', 'rce', 'ssrf', 'csrf', 'open_redirect'
    ]
    
    print("\n=== Testing Exploit Templates ===")
    for vuln_type in template_types:
        template_file = os.path.join(EXPLOITS_PATH, f"{vuln_type}_templates.json")
        if os.path.exists(template_file):
            with open(template_file, 'r', encoding='utf-8') as f:
                try:
                    templates = json.load(f)
                    print(f"[*] Loaded {len(templates)} {vuln_type} exploit templates")
                except json.JSONDecodeError:
                    print(f"[!] Error: Invalid JSON in {vuln_type}_templates.json")
        else:
            print(f"[!] No template file found for {vuln_type}")

if __name__ == "__main__":
    test_payload_loading()
    test_exploit_loading() 