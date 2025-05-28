#!/usr/bin/env python3
import os
import pickle
import numpy as np
import json
from app.model_trainer import VulnerabilityModelTrainer

# Path to the models
MODEL_PATH = "app/models/rce_model.pkl"
SCALER_PATH = "app/models/rce_scaler.pkl"
FEATURES_PATH = "app/models/rce_features.pkl"

# Load the model, scaler, and feature names
with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

with open(SCALER_PATH, 'rb') as f:
    scaler = pickle.load(f)

with open(FEATURES_PATH, 'rb') as f:
    feature_names = pickle.load(f)

# Create a feature extractor instance
feature_extractor = VulnerabilityModelTrainer()

# Edge cases to test
edge_cases = [
    # Obvious RCE cases
    {
        "url": "http://test-app.com/exec?cmd=ls -la",
        "html": "<div>total 20 drwxrwxr-x</div>",
        "description": "Basic command execution, should be detected",
        "is_vulnerable": True
    },
    {
        "url": "http://test-app.com/api/system?command=cat /etc/passwd",
        "html": "<div>root:x:0:0:root:/root:/bin/bash</div>",
        "description": "Direct system command, should be detected",
        "is_vulnerable": True
    },
    # Obfuscated RCE cases
    {
        "url": "http://test-app.com/api?q=${IFS}cat${IFS}/etc/passwd",
        "html": "<div>root:x:0:0:root:/root:/bin/bash</div>",
        "description": "Obfuscated command using IFS variable",
        "is_vulnerable": True
    },
    {
        "url": "http://test-app.com/debug?code=eval(atob('Y2F0IC9ldGMvcGFzc3dk'))",
        "html": "<div>Command executed</div>",
        "description": "Base64 encoded command",
        "is_vulnerable": True
    },
    # Language-specific RCE
    {
        "url": "http://test-app.com/php?cmd=<?php system('id'); ?>",
        "html": "<div>uid=33(www-data) gid=33(www-data)</div>",
        "description": "PHP specific RCE",
        "is_vulnerable": True
    },
    {
        "url": "http://test-app.com/api/run?code=__import__('os').system('id')",
        "html": "<div>uid=1000(user) gid=1000(user)</div>",
        "description": "Python specific RCE",
        "is_vulnerable": True
    },
    {
        "url": "http://test-app.com/node?js=require('child_process').execSync('id')",
        "html": "<div>uid=1000(node) gid=1000(node)</div>",
        "description": "Node.js specific RCE",
        "is_vulnerable": True
    },
    # Tricky false positives (not RCE)
    {
        "url": "http://test-app.com/search?q=how to use system command in programming",
        "html": "<div>Results for: how to use system command in programming</div>",
        "description": "Contains RCE keywords but is a legitimate search",
        "is_vulnerable": False
    },
    {
        "url": "http://test-app.com/docs/exec-command-usage.html",
        "html": "<div>Documentation for exec command</div>",
        "description": "URL contains RCE terms but is documentation",
        "is_vulnerable": False
    },
    {
        "url": "http://test-app.com/code-examples?lang=python&show=subprocess.Popen(['ls', '-la'])",
        "html": "<div><code>subprocess.Popen(['ls', '-la'])</code> - Example of process execution in Python</div>",
        "description": "Code example showing RCE but not executing it",
        "is_vulnerable": False
    },
    # Command injection with WAF bypass techniques
    {
        "url": "http://test-app.com/tool?cmd=p''ing -c 1 localhost",
        "html": "<div>PING localhost (127.0.0.1): 56 data bytes</div>",
        "description": "Command injection with quote insertion",
        "is_vulnerable": True
    },
    {
        "url": "http://test-app.com/api/exec?command=/???/c?t+/etc/p?ssw?",
        "html": "<div>root:x:0:0:root:/root:/bin/bash</div>",
        "description": "Command with wildcards to bypass filters",
        "is_vulnerable": True
    },
    # Template injection
    {
        "url": "http://test-app.com/template?tpl={{7*7}}{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "html": "<div>49uid=33(www-data) gid=33(www-data)</div>",
        "description": "Template injection leading to RCE",
        "is_vulnerable": True
    },
    # Legitimate command usages (not RCE)
    {
        "url": "http://test-app.com/admin/commands?id=create_user",
        "html": "<div>Command: create_user</div><div>Status: Success</div>",
        "description": "Admin page with command parameter but not RCE",
        "is_vulnerable": False
    },
    {
        "url": "http://test-app.com/tool?action=convert&format=base64",
        "html": "<div>Conversion successful</div>",
        "description": "Contains base64 but for legitimate conversion",
        "is_vulnerable": False
    }
]

# Function to extract features from a URL and HTML
def extract_features(url, html):
    features_dict = feature_extractor._extract_features_from_html(url, html, 'rce')
    feature_vector = [features_dict.get(name, 0) for name in feature_names]
    return np.array([feature_vector])

# Test each edge case
print("Testing RCE model against edge cases...")
print("-" * 80)
correct = 0
total = len(edge_cases)

for i, case in enumerate(edge_cases):
    # Extract features
    features = extract_features(case['url'], case['html'])
    
    # Scale features
    features_scaled = scaler.transform(features)
    
    # Predict
    prediction = model.predict(features_scaled)[0]
    probability = model.predict_proba(features_scaled)[0][1]  # Probability of being vulnerable
    
    # Evaluate
    is_correct = prediction == case['is_vulnerable']
    if is_correct:
        correct += 1
    
    # Print results
    print(f"Case {i+1}: {case['description']}")
    print(f"URL: {case['url']}")
    print(f"Expected: {'Vulnerable' if case['is_vulnerable'] else 'Not Vulnerable'}")
    print(f"Predicted: {'Vulnerable' if prediction else 'Not Vulnerable'} (Probability: {probability:.2f})")
    print(f"Result: {'✅ Correct' if is_correct else '❌ Incorrect'}")
    print("-" * 80)

# Print summary
accuracy = correct / total * 100
print(f"Edge Case Testing Summary:")
print(f"Correctly classified: {correct}/{total} ({accuracy:.1f}%)")

# Identify most important features for the model
if hasattr(model, 'feature_importances_'):
    importances = model.feature_importances_
    indices = np.argsort(importances)[::-1]
    
    print("\nTop 10 most important features:")
    for i in range(min(10, len(feature_names))):
        idx = indices[i]
        print(f"{feature_names[idx]}: {importances[idx]:.4f}") 