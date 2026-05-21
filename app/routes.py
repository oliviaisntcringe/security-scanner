"""
Flask routes for VulnScan web dashboard.
"""
import asyncio
import glob
import json
import os
import threading
import datetime
from pathlib import Path
from functools import wraps

from flask import (
    Blueprint, render_template, request, jsonify,
    session, redirect, url_for, send_file, abort,
)
from . import socketio
from .config import RESULTS_DIR, REPORTS_DIR

main = Blueprint('main', __name__)

# Severity mapping used across routes
_SEVERITY = {
    'xss': 'high', 'sqli': 'critical', 'rce': 'critical',
    'file_inclusion': 'critical', 'lfi': 'critical', 'rfi': 'critical',
    'ssrf': 'high', 'csrf': 'medium', 'open_redirect': 'medium',
    'cors': 'medium', 'ssl_tls': 'medium', 'subdomain_takeover': 'high',
    'xxe': 'high', 'nosql': 'high',
}

# ── Lazy scanner import (avoids import-time crash if Flask runs standalone) ───
_scanner = None
def _get_scanner():
    global _scanner
    if _scanner is None:
        try:
            from scanner.core.orchestrator import Orchestrator
            _scanner = Orchestrator
        except ImportError:
            _scanner = None
    return _scanner


# ── Auth ───────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


# ── Pages ──────────────────────────────────────────────────────────────────────

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/login', methods=['POST'])
def login():
    data = request.json or {}
    # Default credentials — change via env vars in production
    admin_user = os.environ.get('VULNSCAN_USER', 'admin')
    admin_pass = os.environ.get('VULNSCAN_PASS', 'vulnscan')
    if data.get('username') == admin_user and data.get('password') == admin_pass:
        session['logged_in'] = True
        return jsonify({'status': 'ok'})
    return jsonify({'error': 'Invalid credentials'}), 401

@main.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('main.index'))


# ── Scan ───────────────────────────────────────────────────────────────────────

# Track active scan thread
_scan_state = {'running': False, 'result': None}

@main.route('/scan', methods=['POST'])
def manual_scan():
    """Start a scan from the web UI."""
    if _scan_state['running']:
        return jsonify({'error': 'Scan already running'}), 409

    data = request.json or {}
    url  = (data.get('url') or '').strip()
    if not url:
        return jsonify({'error': 'No URL'}), 400

    modules_raw = data.get('modules', 'all')
    if modules_raw == 'all':
        from scanner.core.orchestrator import MODULES
        modules = list(MODULES.keys())
    else:
        modules = [m.strip() for m in modules_raw.split(',') if m.strip()]

    def _run():
        _scan_state['running'] = True
        try:
            from scanner.core.orchestrator import Orchestrator
            from scanner.utils.notify import notify_report
            from scanner.utils import report as report_util

            socketio.emit('log', f'[*] Starting scan: {url}')

            orc = Orchestrator(
                modules=modules,
                depth=int(data.get('depth', 3)),
                max_urls=int(data.get('max_urls', 50)),
                threads=int(data.get('threads', 5)),
                proxy=data.get('proxy') or None,
                timeout=int(data.get('timeout', 30)),
                use_ml=bool(data.get('ml', True)),
                verbose=bool(data.get('verbose', False)),
                notify_each=bool(data.get('notify_each', False)),
            )

            result = asyncio.run(orc.scan_target(url))

            # Emit each finding via socket
            for f in result.findings:
                f.setdefault('severity', _SEVERITY.get(f.get('type', ''), 'medium'))
                socketio.emit('vuln_found', f)
                socketio.emit('log', f"[+] {f['type'].upper()} — {f.get('parameter')} — {f.get('url')}")

            # Generate report
            fmt = data.get('format', 'html')
            rp  = report_util.generate(
                target=url,
                findings=result.findings,
                urls_crawled=result.urls_crawled,
                elapsed=result.elapsed,
                fmt=fmt,
            )
            socketio.emit('log', f'[*] Report saved: {rp.name}')
            socketio.emit('scan_done', {'findings': len(result.findings), 'report': str(rp)})

            # Telegram
            if data.get('telegram') and os.environ.get('TELEGRAM_TOKEN'):
                counts = {}
                for f in result.findings:
                    s = f.get('severity', 'medium')
                    counts[s] = counts.get(s, 0) + 1
                summary = f"Target: {url}\n" + "\n".join(f"  {k.upper()}: {v}" for k, v in counts.items())
                asyncio.run(notify_report(rp, summary))

        except Exception as e:
            socketio.emit('log', f'[!] Scan error: {e}')
            socketio.emit('scan_done', {'error': str(e)})
        finally:
            _scan_state['running'] = False

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return jsonify({'status': 'started'})


@main.route('/scan/stop', methods=['POST'])
def stop_scan():
    _scan_state['running'] = False
    return jsonify({'status': 'stopped'})


# ── Vulnerabilities ────────────────────────────────────────────────────────────

@main.route('/api/vulns')
def api_vulns():
    """Return all vulnerabilities from result files."""
    vulns   = []
    seen    = set()
    rdir    = RESULTS_DIR
    rdir2   = REPORTS_DIR

    def _load_dir(d):
        for fn in glob.glob(os.path.join(str(d), '*.json')):
            try:
                with open(fn) as f:
                    data = json.load(f)
                for v in data.get('vulnerabilities', data.get('findings', [])):
                    v.setdefault('severity', _SEVERITY.get(v.get('type', ''), 'medium'))
                    key = (v.get('url'), v.get('type'), v.get('parameter'))
                    if key not in seen:
                        seen.add(key)
                        vulns.append(v)
            except Exception:
                pass

    _load_dir(rdir)
    _load_dir(rdir2)
    return jsonify(vulns)


# ── Reports ────────────────────────────────────────────────────────────────────

@main.route('/reports/list')
def reports_list():
    """List generated report files."""
    files = []
    for p in Path(REPORTS_DIR).glob('vulnscan_*'):
        stat = p.stat()
        ext  = p.suffix.lstrip('.')
        files.append({
            'name':   p.name,
            'format': ext,
            'size':   f"{stat.st_size // 1024 or 1} KB",
            'date':   datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M'),
        })
    files.sort(key=lambda x: x['date'], reverse=True)
    return jsonify(files)


@main.route('/reports/download/<path:filename>')
def report_download(filename):
    """Download a report file."""
    path = Path(REPORTS_DIR) / filename
    if not path.exists() or not path.resolve().is_relative_to(Path(REPORTS_DIR).resolve()):
        abort(404)
    return send_file(str(path), as_attachment=True)


@main.route('/reports/latest_html')
def latest_html():
    files = sorted(Path(REPORTS_DIR).glob('vulnscan_*.html'), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        abort(404)
    return files[0].read_text(), 200, {'Content-Type': 'text/html'}


@main.route('/reports/latest_json')
def latest_json():
    files = sorted(Path(REPORTS_DIR).glob('vulnscan_*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    if not files:
        return jsonify([])
    return files[0].read_text(), 200, {'Content-Type': 'application/json'}


# ── Targets ────────────────────────────────────────────────────────────────────

@main.route('/api/targets')
def list_targets():
    """Derive known targets from scan results."""
    vulns = json.loads(api_vulns().data)
    hosts = list(dict.fromkeys(
        v.get('url', '').split('?')[0].split('#')[0]
        .rsplit('/', 1)[0]
        for v in vulns if v.get('url')
    ))
    return jsonify(hosts)


@main.route('/api/targets/rescan', methods=['POST'])
def rescan_target():
    target = (request.json or {}).get('target', '')
    if not target:
        return jsonify({'error': 'No target'}), 400
    # Re-use scan route logic
    request._cached_json = (request.json or {})
    return manual_scan()


# ── Scan status ────────────────────────────────────────────────────────────────

@main.route('/api/scan/status')
def scan_status():
    return jsonify({'status': 'running' if _scan_state['running'] else 'idle'})


# ── Settings ───────────────────────────────────────────────────────────────────

@main.route('/api/settings', methods=['POST'])
def save_settings():
    """Persist settings to scanner config file."""
    data = request.json or {}
    try:
        import configparser
        conf_path = Path.home() / '.vulnscan.conf'
        conf = configparser.ConfigParser()
        if conf_path.exists():
            conf.read(conf_path)
        if 'DEFAULT' not in conf:
            conf['DEFAULT'] = {}
        if data.get('telegram_token'):
            conf['DEFAULT']['TELEGRAM_TOKEN']   = data['telegram_token']
        if data.get('telegram_chat_id'):
            conf['DEFAULT']['TELEGRAM_CHAT_ID'] = data['telegram_chat_id']
        if 'depth'    in data: conf['DEFAULT']['MAX_CRAWL_DEPTH'] = str(data['depth'])
        if 'max_urls' in data: conf['DEFAULT']['MAX_URLS']        = str(data['max_urls'])
        with open(conf_path, 'w') as f:
            conf.write(f)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── WebSocket ──────────────────────────────────────────────────────────────────

@socketio.on('connect')
def handle_connect():
    socketio.emit('log', '[*] Dashboard connected')

@socketio.on('disconnect')
def handle_disconnect():
    pass
