#!/usr/bin/env python3
import os
import json
import time

# Define the vulnerability details
vuln_type = "sqli"
url = "https://example.com/test-enhanced"
confidence = 0.85
evidence = "The ML model detected patterns consistent with this vulnerability type based on: Database query patterns, SQL-like syntax in parameters, or error-based SQL signatures."
example_payload = "' OR 1=1; --"

# Create the vulnerability entry
result = {
    'type': vuln_type,
    'url': url,
    'confidence': confidence,
    'predicted': True,
    'details': f"ML model detected {vuln_type} vulnerability with {confidence:.2f} confidence",
    'parameter': 'Multiple potential parameters detected',
    'payload': f"Example: {example_payload} (Not actually used - ML detection is non-intrusive)",
    'evidence': evidence,
    'detected_by': 'machine_learning',
    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
}

# Determine the path to the results directory
current_dir = os.path.dirname(os.path.abspath(__file__))
results_dir = os.path.join(current_dir, "results")
os.makedirs(results_dir, exist_ok=True)

# Path to consolidated file
consolidated_file = os.path.join(results_dir, 'all_vulnerabilities.json')

# Initialize or load existing vulnerabilities
all_vulns = {'vulnerabilities': []}
if os.path.exists(consolidated_file):
    try:
        with open(consolidated_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'vulnerabilities' in data:
                all_vulns = data
    except Exception as e:
        print(f"Error loading vulnerability database: {e}")

# Add this vulnerability
all_vulns['vulnerabilities'].append(result)

# Update metadata
all_vulns['metadata'] = {
    'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
    'total_vulnerabilities': len(all_vulns['vulnerabilities']),
    'last_scan_url': url,
    'last_scan_vulnerabilities': 1
}

# Save updated file
try:
    with open(consolidated_file, 'w') as f:
        json.dump(all_vulns, f, indent=2)
    print(f"Added {vuln_type} vulnerability for {url} to consolidated database")
except Exception as e:
    print(f"Error saving to vulnerability database: {e}")

print("\nEnhanced vulnerability entry added. Now generate a new report to see it.") 