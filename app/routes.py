import os
import json
import threading
import asyncio
from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for
from .scanners.advanced_scanner import AdvancedScanner
from . import socketio
from .config import RESULTS_DIR
from functools import wraps
from app.config import REPORTS_DIR

main = Blueprint('main', __name__)
scanner = AdvancedScanner()

@main.route('/')
def index():
    """Render the C2-like interface"""
    return render_template('index.html')

@main.route('/scan', methods=['POST'])
def manual_scan():
    """Handle manual scan requests"""
    url = request.form.get('url')
    if url:
        threading.Thread(
            target=asyncio.run,
            args=(scanner.scan_site(url),)
        ).start()
        return jsonify({'status': 'started'})
    return '', 204

@main.route('/results')
def get_results():
    """Get all scan results"""
    results = {}
    for file in os.listdir(RESULTS_DIR):
        if file.endswith('.html'):
            vuln_type = file.split('_')[0]
            with open(os.path.join(RESULTS_DIR, file)) as f:
                results[vuln_type] = f.read()
    return jsonify(results)

@main.route('/targets', methods=['POST'])
def add_target():
    """Add a new target to the scan list"""
    target = request.json.get('target')
    if target:
        if target not in scanner.TEST_TARGETS:
            scanner.TEST_TARGETS.append(target)
            return jsonify({'status': 'success'})
    return jsonify({'status': 'error'}), 400

@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection"""
    socketio.emit('log', '[*] Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    """Handle WebSocket disconnection"""
    socketio.emit('log', '[*] Client disconnected')

@main.route('/api/vulns')
def api_vulns():
    """Return all vulnerabilities as a JSON array for the C2 dashboard table"""
    import glob
    import json
    import os
    # Severity mapping
    severity_map = {
        'xxe': 'critical',
        'sqli': 'critical',
        'file_inclusion': 'critical',
        'ssrf': 'high',
        'xss': 'high',
        'open_redirect': 'medium',
        'cors': 'medium',
        'ssl_tls': 'medium',
        'subdomain_takeover': 'high',
        'rce': 'critical',
        'lfi': 'critical',
        'ssti': 'high',
        'csrf': 'medium',
        'nosql': 'high',
        'jwt': 'high'
    }
    
    include_all = request.args.get('include_all', 'false').lower() == 'true'
    vulns = []
    
    # First check for consolidated file in RESULTS_DIR
    if include_all and os.path.exists(RESULTS_DIR):
        consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
        if os.path.exists(consolidated_file):
            try:
                with open(consolidated_file, 'r') as f:
                    data = json.load(f)
                    for vuln in data.get('vulnerabilities', []):
                        vuln['severity'] = severity_map.get(vuln['type'], 'medium')
                        vulns.append(vuln)
            except Exception as e:
                print(f"Error loading consolidated file: {e}")
    
        # Check individual result files
        for filename in glob.glob(os.path.join(RESULTS_DIR, '*.json')):
            if filename.endswith('all_vulnerabilities.json'): 
                continue  # Skip the consolidated file we already processed
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                    for vuln in data.get('vulnerabilities', []):
                        vuln['severity'] = severity_map.get(vuln['type'], 'medium')
                        # Check for duplicate before adding
                        is_duplicate = False
                        for existing in vulns:
                            if (existing.get('url') == vuln.get('url') and 
                                existing.get('type') == vuln.get('type') and
                                existing.get('parameter') == vuln.get('parameter')):
                                is_duplicate = True
                                break
                        if not is_duplicate:
                            vulns.append(vuln)
            except Exception as e:
                print(f"Error loading file {filename}: {e}")
                continue
    
    # Also check REPORTS_DIR for additional vulns
    for filename in glob.glob(os.path.join(REPORTS_DIR, '*.json')):
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                for vuln in data.get('vulnerabilities', []):
                    vuln['severity'] = severity_map.get(vuln['type'], 'medium')
                    # Check for duplicate before adding
                    is_duplicate = False
                    for existing in vulns:
                        if (existing.get('url') == vuln.get('url') and 
                            existing.get('type') == vuln.get('type') and
                            existing.get('parameter') == vuln.get('parameter')):
                            is_duplicate = True
                            break
                    if not is_duplicate:
                        vulns.append(vuln)
        except Exception as e:
            continue
    
    # If no vulnerabilities found, provide sample data for testing the interface
    if not vulns:
        vulns = [
            {
                "id": "vuln-001",
                "type": "xss",
                "severity": "high",
                "url": "https://example.com/search?q=test",
                "parameter": "q",
                "payload": "<script>alert(1)</script>",
                "context": "HTML body",
                "evidence": "<div>test<script>alert(1)</script></div>",
                "timestamp": "2023-05-18T14:32:45",
                "details": "Reflected XSS in search parameter"
            },
            {
                "id": "vuln-002",
                "type": "sqli",
                "severity": "critical",
                "url": "https://example.com/users?id=1",
                "parameter": "id",
                "payload": "1' OR 1=1 --",
                "context": "SQL Query",
                "evidence": "Error: unterminated string literal at or near \"' OR\"",
                "timestamp": "2023-05-18T15:10:22",
                "details": "SQL injection in user ID parameter"
            },
            {
                "id": "vuln-003",
                "type": "lfi",
                "severity": "critical",
                "url": "https://example.com/include?file=../../../etc/passwd",
                "parameter": "file",
                "payload": "../../../etc/passwd",
                "context": "File include",
                "evidence": "root:x:0:0:root:/root:/bin/bash\nbin:x:1:1:bin:/bin:/usr/bin/nologin",
                "timestamp": "2023-05-19T09:12:03",
                "details": "Local file inclusion vulnerability"
            }
        ]
    
    return jsonify(vulns)

@main.route('/reports/latest_html')
def latest_html():
    """Serve the latest HTML report for export"""
    import glob
    import os
    files = glob.glob(os.path.join(REPORTS_DIR, 'zodiac_crawler_report_*.html'))
    if not files:
        # Fallback to old naming pattern if no files found with new pattern
        files = glob.glob(os.path.join(REPORTS_DIR, 'full_report_*.html'))
        if not files:
            return 'No report found', 404
    latest = max(files, key=os.path.getctime)
    with open(latest) as f:
        return f.read(), 200, {'Content-Type': 'text/html'}

@main.route('/reports/latest_json')
def latest_json():
    """Serve the latest JSON scan result for export"""
    import glob
    import os
    files = glob.glob(os.path.join(REPORTS_DIR, 'zodiac_crawler_data_*.json'))
    if not files:
        # Fallback to old naming pattern if no files found with new pattern
        files = glob.glob(os.path.join(REPORTS_DIR, 'scan_*.json'))
        if not files:
            return jsonify([])
    latest = max(files, key=os.path.getctime)
    with open(latest) as f:
        return f.read(), 200, {'Content-Type': 'application/json'}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated

@main.route('/login', methods=['POST'])
def login():
    data = request.json or request.form
    if data.get('username') == 'admin' and data.get('password') == 'admin':
        session['logged_in'] = True
        return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'msg': 'Invalid credentials'}), 401

@main.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('main.index'))

@main.route('/scan/pause', methods=['POST'])
@login_required
def pause_scan():
    scanner.running = False
    return jsonify({'status': 'paused'})

@main.route('/scan/resume', methods=['POST'])
@login_required
def resume_scan():
    scanner.running = True
    return jsonify({'status': 'resumed'})

@main.route('/scan/stop', methods=['POST'])
@login_required
def stop_scan():
    scanner.running = False
    scanner.cleanup()
    return jsonify({'status': 'stopped'})

@main.route('/api/vulns/delete', methods=['POST'])
@login_required
def delete_vuln():
    idx = request.json.get('idx')
    # Implement deletion logic (e.g., mark as deleted in file/db)
    return jsonify({'status': 'deleted'})

@main.route('/api/vulns/ignore', methods=['POST'])
@login_required
def ignore_vuln():
    idx = request.json.get('idx')
    # Implement ignore logic (e.g., mark as ignored in file/db)
    return jsonify({'status': 'ignored'})

@main.route('/api/targets')
@login_required
def list_targets():
    # Get targets from scanner or provide sample targets for testing
    targets = getattr(scanner, 'TEST_TARGETS', [])
    
    # If no targets found, provide sample data for testing the interface
    if not targets:
        targets = [
            "https://example.com",
            "https://test.example.org",
            "https://vulnerable.example.net"
        ]
    
    return jsonify(targets)

@main.route('/api/targets/rescan', methods=['POST'])
@login_required
def rescan_target():
    target = request.json.get('target')
    if target:
        threading.Thread(
            target=asyncio.run,
            args=(scanner.scan_site(target),)
        ).start()
        return jsonify({'status': 'rescanning'})
    return jsonify({'status': 'error', 'msg': 'No target specified'}), 400

@main.route('/api/targets/remove', methods=['POST'])
@login_required
def remove_target():
    target = request.json.get('target')
    if target and target in scanner.TEST_TARGETS:
        scanner.TEST_TARGETS.remove(target)
        return jsonify({'status': 'removed'})
    return jsonify({'status': 'removed'})  # Return success even if not found

@main.route('/api/targets/history', methods=['POST'])
@login_required
def target_history():
    target = request.json.get('target')
    # Implement history retrieval (simulated for now)
    history = [
        {"date": "2023-05-18T14:30:00", "vulns_found": 5},
        {"date": "2023-05-17T10:15:00", "vulns_found": 3},
        {"date": "2023-05-15T09:20:00", "vulns_found": 7}
    ]
    return jsonify({'history': history})

@main.route('/api/scan/status')
@login_required
def scan_status():
    status = {
        'status': 'running' if scanner.running else 'paused',
        'total_scans': 152,  # Sample data
        'success_rate': '95%',
        'proxy_count': 8,
        'avg_time': '42s'
    }
    return jsonify(status)

@main.route('/api/settings', methods=['POST'])
@login_required
def save_settings():
    # Get the settings from the request and save them
    settings = request.json
    # In a real implementation, save to database or config file
    # For now, just return success
    return jsonify({'status': 'success'})

@main.route('/api/notify', methods=['POST'])
@login_required
def notify():
    # Implement notification logic (e.g., send toasts, Telegram, etc.)
    return jsonify({'status': 'notified'})

@main.route('/api/vulns/export', methods=['POST'])
@login_required
def export_selected():
    vulns = request.json.get('vulns', [])
    # Implement export logic
    return jsonify({'status': 'exported'}) 