import os
import json
import time
import traceback
from datetime import datetime
from ..utils.helpers import LOG
from ..config import RESULTS_DIR, REPORTS_DIR, ML_DEBUG
from ..utils.telegram_notifier import send_report_to_telegram, send_vulnerability_alert
import html

class ReportGenerator:
    @staticmethod
    async def generate_html_report(send_telegram=True):
        """Generate a comprehensive HTML report and optionally send to Telegram"""
        try:
            # Initialize counters and containers
            total_vulns = 0
            total_loaded = 0
            vuln_reports = {}
            vuln_types = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Severity mapping for different vulnerability types
            severity_map = {
                'xss': 'high',
                'sqli': 'critical',
                'rce': 'critical',
                'lfi': 'high',
                'ssrf': 'high',
                'csrf': 'medium',
                'open_redirect': 'medium',
                'cors': 'medium',
                'ssl_tls': 'medium',
                'subdomain_takeover': 'high',
                'xxe': 'high'
            }
            
            # First load results from RESULTS_DIR
            LOG("[*] Loading scan results...")
            if not os.path.exists(RESULTS_DIR):
                os.makedirs(RESULTS_DIR)
                LOG("[!] Created results directory")
                return None
                
            # Check for consolidated vulnerabilities file first
            consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
            if os.path.exists(consolidated_file):
                try:
                    with open(consolidated_file, 'r') as f:
                        data = json.load(f)
                        vulns = data.get('vulnerabilities', [])
                        if vulns:
                            LOG(f"[reportgen] Loaded {len(vulns)} vulns from consolidated file")
                            total_loaded += len(vulns)
                            for vuln in vulns:
                                vuln_type = vuln.get('type', 'unknown')
                                if vuln_type not in vuln_reports:
                                    vuln_reports[vuln_type] = []
                                vuln_reports[vuln_type].append(vuln)
                                total_vulns += 1
                                severity = severity_map.get(vuln_type, 'medium')
                                vuln_types[severity] += 1
                except Exception as e:
                    LOG(f"[!] Error reading consolidated file: {e}")
                    if ML_DEBUG:
                        LOG(f"[!] Stack trace: {traceback.format_exc()}")
            
            # Then check individual result files (in case some weren't added to consolidated file)
            results_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.json') and f != 'all_vulnerabilities.json']
            if not results_files and total_vulns == 0:
                LOG("[!] No scan results found")
                return None
                
            for filename in results_files:
                try:
                    with open(os.path.join(RESULTS_DIR, filename), 'r') as f:
                        data = json.load(f)
                        vulns = data.get('vulnerabilities', [])
                        if vulns:
                            LOG(f"[reportgen] Loaded {len(vulns)} vulns from {filename}")
                            total_loaded += len(vulns)
                            for vuln in vulns:
                                vuln_type = vuln.get('type', 'unknown')
                                
                                # Check for duplicates
                                url = vuln.get('url', '')
                                is_duplicate = False
                                if vuln_type in vuln_reports:
                                    for existing_vuln in vuln_reports[vuln_type]:
                                        if existing_vuln.get('url', '') == url:
                                            is_duplicate = True
                                            break
                                
                                # Only add non-duplicates
                                if not is_duplicate:
                                    if vuln_type not in vuln_reports:
                                        vuln_reports[vuln_type] = []
                                    vuln_reports[vuln_type].append(vuln)
                                    total_vulns += 1
                                    severity = severity_map.get(vuln_type, 'medium')
                                    vuln_types[severity] += 1
                except Exception as e:
                    LOG(f"[!] Error reading report {filename}: {e}")
                    if ML_DEBUG:
                        LOG(f"[!] Stack trace: {traceback.format_exc()}")
                    continue
                    
            LOG(f"[reportgen] Total loaded vulns: {total_vulns}")
            
            if total_vulns == 0:
                LOG("[!] No vulnerabilities found in any scan")
                return None
            else:
                LOG(f"[*] Found {total_vulns} vulnerabilities for report generation")
                vuln_summary = {}
                for vuln_type in vuln_reports.keys():
                    vuln_summary[vuln_type] = len(vuln_reports[vuln_type])
                    
                LOG(f"[*] Vulnerability types detected: {', '.join([f'{k}:{v}' for k, v in vuln_summary.items()])}")
                
            # Generate HTML report
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = os.path.join(REPORTS_DIR, f"zodiac_crawler_report_{timestamp}.html")
            
            # Create report directory if it doesn't exist
            os.makedirs(REPORTS_DIR, exist_ok=True)
            
            with open(report_file, 'w', encoding='utf-8') as f:
                # Write HTML header with improved CSS styling
                f.write("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Zodiac Crawler Report</title>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.8.1/font/bootstrap-icons.css" rel="stylesheet">
                    <style>
                        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 0; }
                        .topbar { 
                            background: #2c3e50; 
                            color: white; 
                            padding: 1rem; 
                            position: sticky;
                            top: 0;
                            z-index: 1000;
                            display: flex;
                            justify-content: space-between;
                            align-items: center;
                        }
                        .btn-print {
                            background: transparent;
                            border: 1px solid white;
                            color: white;
                            padding: 0.5rem 1rem;
                            border-radius: 4px;
                            cursor: pointer;
                        }
                        .btn-print:hover {
                            background: rgba(255,255,255,0.1);
                        }
                        .dashboard-widget {
                            background: white;
                            border-radius: 8px;
                            padding: 1rem;
                            text-align: center;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                            margin-bottom: 1rem;
                        }
                        .dashboard-widget .stat {
                            font-size: 2rem;
                            font-weight: bold;
                            margin-bottom: 0.5rem;
                        }
                        .dashboard-widget .label {
                            color: #666;
                            font-size: 0.9rem;
                        }
                        .vuln-entry { 
                            background: white;
                            border-radius: 8px;
                            padding: 1.5rem;
                            margin-bottom: 1rem;
                            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        }
                        .critical { border-left: 5px solid #dc3545; }
                        .high { border-left: 5px solid #fd7e14; }
                        .medium { border-left: 5px solid #ffc107; }
                        .low { border-left: 5px solid #28a745; }
                        .details { margin: 1rem 0; }
                        .payload { 
                            background: #f8f9fa; 
                            padding: 1rem;
                            border-radius: 4px;
                            font-family: 'Courier New', Courier, monospace;
                            overflow-x: auto;
                        }
                        .timestamp {
                            color: #666;
                            font-size: 0.9rem;
                        }
                        @media print {
                            .topbar { position: static; }
                            .btn-print { display: none; }
                            .vuln-entry { break-inside: avoid; }
                        }
                    </style>
                </head>
                <body>
                    <div class='topbar'>
                        <span class='fs-4 fw-bold'><i class='bi bi-shield-lock'></i> Zodiac Crawler Report</span>
                        <button class='btn btn-print' onclick='window.print()'><i class='bi bi-printer'></i> Print/Export</button>
                    </div>
                    <div class='container mt-4'>
                        <div class='mb-3'><span class='timestamp'>Generated on: %s</span></div>
                        <!-- Dashboard Summary Widgets -->
                        <div class='row mb-4'>
                            <div class='col-md-2 col-6'><div class='dashboard-widget'><div class='stat'>%d</div><div class='label'>Total Vulns</div></div></div>
                            <div class='col-md-2 col-6'><div class='dashboard-widget'><div class='stat'>%d</div><div class='label'>Critical</div></div></div>
                            <div class='col-md-2 col-6'><div class='dashboard-widget'><div class='stat'>%d</div><div class='label'>High</div></div></div>
                            <div class='col-md-2 col-6'><div class='dashboard-widget'><div class='stat'>%d</div><div class='label'>Medium</div></div></div>
                            <div class='col-md-2 col-6'><div class='dashboard-widget'><div class='stat'>%d</div><div class='label'>Low</div></div></div>
                        </div>
                """ % (
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    total_vulns,
                    vuln_types['critical'],
                    vuln_types['high'],
                    vuln_types['medium'],
                    vuln_types['low']
                ))
                
                # Write vulnerability details grouped by severity
                severity_order = ['critical', 'high', 'medium', 'low']
                for severity in severity_order:
                    # Get all vulnerabilities of this severity
                    severity_vulns = []
                    for vuln_type, vulns in vuln_reports.items():
                        if severity_map.get(vuln_type, 'medium') == severity:
                            severity_vulns.extend(vulns)
                            
                    if severity_vulns:
                        f.write(f"""
                        <div class='vuln-section mb-4'>
                            <h2 class='mb-3'>{severity.upper()} Severity Vulnerabilities</h2>
                        """)
                        
                        for vuln in severity_vulns:
                            vuln_type = vuln.get('type', 'unknown').upper()
                            url = vuln.get('url', 'N/A')
                            confidence = vuln.get('confidence', 'N/A')
                            detected_by = vuln.get('detected_by', 'N/A')
                            details = vuln.get('details', '')
                            payload = vuln.get('payload', 'N/A')
                            parameter = vuln.get('parameter', 'N/A')
                            evidence = vuln.get('evidence', '')
                            timestamp = vuln.get('timestamp', '')
                            
                            # Include ML debug info if available
                            debug_info = ''
                            if ML_DEBUG and 'debug_info' in vuln:
                                debug = vuln['debug_info']
                                if debug:
                                    debug_info = f"""
                                    <div class='mt-3'>
                                        <p><strong>Debug Information:</strong></p>
                                        <pre class='payload'>{html.escape(json.dumps(debug, indent=2))}</pre>
                                    </div>
                                    """
                            
                            f.write(f"""
                            <div class='vuln-entry {severity}'>
                                <h3>{vuln_type}</h3>
                                <p><strong>URL:</strong> <a href="{html.escape(url)}" target="_blank">{html.escape(url)}</a></p>
                                <p><strong>Confidence:</strong> {confidence}</p>
                                <p><strong>Detected By:</strong> {detected_by}</p>
                                <p><strong>Parameter:</strong> {html.escape(parameter)}</p>
                                <p><strong>Timestamp:</strong> {timestamp}</p>
                                <div class='details'>
                                    <p><strong>Details:</strong></p>
                                    <p>{html.escape(details)}</p>
                                    <p><strong>Evidence:</strong></p>
                                    <p>{html.escape(evidence)}</p>
                                    <p><strong>Payload:</strong></p>
                                    <pre class='payload'><code>{html.escape(str(payload))}</code></pre>
                                    {debug_info}
                                </div>
                            </div>
                            """)
                            
                        f.write("</div>")
                
                # Close HTML
                f.write("""
                    </div>
                    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
                </body>
                </html>
                """)
                
            LOG(f"[*] Report generated: {report_file}")
            
            # Send to Telegram if enabled
            if send_telegram:
                try:
                    result = await send_report_to_telegram(report_file)
                    if result:
                        LOG("[*] Report sent to Telegram successfully")
                    else:
                        LOG("[!] Failed to send report to Telegram - check your Telegram bot configuration")
                except Exception as e:
                    LOG(f"[!] Error sending report to Telegram: {e}")
                    if ML_DEBUG:
                        LOG(f"[!] Stack trace: {traceback.format_exc()}")
            
            return report_file
            
        except Exception as e:
            LOG(f"[!] Error generating report: {e}")
            if ML_DEBUG:
                LOG(f"[!] Stack trace: {traceback.format_exc()}")
            return None 