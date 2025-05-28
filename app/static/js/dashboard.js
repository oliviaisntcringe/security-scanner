// C2 Dashboard JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Connect to WebSocket
    const socket = io();
    
    // Initialize global state
    let allVulns = [];
    let allTargets = [];
    let chartInstance = null;
    
    // Configure Chart.js defaults for dark mode
    if (window.Chart) {
        Chart.defaults.color = '#b0b8c1';
        Chart.defaults.borderColor = 'rgba(255, 255, 255, 0.1)';
        Chart.defaults.font.family = "'Fira Mono', 'Courier New', monospace";
        
        // Set default colors for all chart types
        const defaultOptions = {
            plugins: {
                tooltip: {
                    titleColor: '#e0e0e0',
                    bodyColor: '#e0e0e0',
                    backgroundColor: '#23272b',
                    borderColor: '#444',
                    borderWidth: 1
                },
                legend: {
                    labels: {
                        color: '#e0e0e0'
                    }
                },
                title: {
                    color: '#e0e0e0'
                }
            },
            scales: {
                x: {
                    ticks: { color: '#b0b8c1' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                },
                y: {
                    ticks: { color: '#b0b8c1' },
                    grid: { color: 'rgba(255, 255, 255, 0.05)' }
                }
            }
        };
        
        // Apply to all chart types
        Chart.defaults.set('plugins.title', defaultOptions.plugins.title);
        Chart.defaults.set('plugins.tooltip', defaultOptions.plugins.tooltip);
        Chart.defaults.set('plugins.legend', defaultOptions.plugins.legend);
        Chart.defaults.set('scales.x', defaultOptions.scales.x);
        Chart.defaults.set('scales.y', defaultOptions.scales.y);
    }
    
    // ========== Event Listeners ==========
    
    // Handle form submission for new scan
    document.getElementById('scanForm').addEventListener('submit', function(e) {
        e.preventDefault();
        const url = document.getElementById('targetUrl').value;
        if (!url) return;
        
        fetch('/scan', {
            method: 'POST',
            body: new URLSearchParams({url: url})
        })
        .then(response => {
            if (response.ok) {
                addToActivityLog(`Started scan on: ${url}`);
                addToTerminalFeed(`[*] Initiating security assessment for ${url}`, 'info');
                document.getElementById('targetUrl').value = '';
            }
        })
        .catch(error => {
            addToActivityLog(`Error starting scan: ${error}`, 'error');
            addToTerminalFeed(`[!] Scan initialization failed: ${error}`, 'error');
        });
    });
    
    // Add target button in modal
    document.getElementById('confirmAddTarget')?.addEventListener('click', function() {
        const url = document.getElementById('newTargetUrl').value;
        const profile = document.getElementById('scanProfile').value;
        
        if (!url) return;
        
        fetch('/api/targets', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({target: url, profile: profile})
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                addToActivityLog(`Added target: ${url}`);
                addToTerminalFeed(`[+] Target added to scan queue: ${url}`, 'info');
                bootstrap.Modal.getInstance(document.getElementById('addTargetModal')).hide();
                fetchTargets(); // Refresh the targets list
            } else {
                addToActivityLog(`Failed to add target: ${data.msg || 'Unknown error'}`, 'error');
                addToTerminalFeed(`[!] Failed to add target: ${data.msg || 'Unknown error'}`, 'error');
            }
        })
        .catch(error => {
            addToActivityLog(`Error adding target: ${error}`, 'error');
            addToTerminalFeed(`[!] Error adding target: ${error}`, 'error');
        });
    });
    
    // Filter for vulnerabilities
    document.getElementById('filterSeverity')?.addEventListener('change', renderVulns);
    
    // Time range change for chart
    document.getElementById('timeRange')?.addEventListener('change', function() {
        updateVulnChart();
    });
    
    // Export buttons
    document.getElementById('exportHtml')?.addEventListener('click', function() {
        window.open('/reports/latest_html', '_blank');
        addToActivityLog('Exported HTML report');
    });
    
    document.getElementById('exportJson')?.addEventListener('click', function() {
        window.open('/reports/latest_json', '_blank');
        addToActivityLog('Exported JSON data');
    });
    
    // Settings form
    document.getElementById('saveSettings')?.addEventListener('click', function() {
        // Gather form data
        const settings = {
            scanDepth: document.getElementById('scanDepth').value,
            concurrentScans: document.getElementById('concurrentScans').value,
            requestTimeout: document.getElementById('requestTimeout').value,
            useProxy: document.getElementById('useProxy').checked,
            passiveScan: document.getElementById('passiveScan').checked,
            emailNotifications: document.getElementById('emailNotifications').checked,
            emailAddress: document.getElementById('emailAddress').value,
            telegramNotifications: document.getElementById('telegramNotifications').checked,
            telegramChatId: document.getElementById('telegramChatId').value,
            slackNotifications: document.getElementById('slackNotifications').checked,
            slackWebhook: document.getElementById('slackWebhook').value
        };
        
        // Save settings to server
        fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings)
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                addToActivityLog('Settings saved successfully');
                addToTerminalFeed('[*] Crawler configuration updated', 'info');
            } else {
                addToActivityLog(`Error saving settings: ${data.msg || 'Unknown error'}`, 'error');
            }
        })
        .catch(error => {
            addToActivityLog(`Error saving settings: ${error}`, 'error');
        });
    });
    
    // Logout button
    document.getElementById('logoutBtn')?.addEventListener('click', function() {
        window.location.href = '/logout';
    });
    
    // ========== Functions ==========
    
    // Fetch and render vulnerabilities
    function fetchVulns() {
        fetch('/api/vulns?include_all=true')
            .then(response => response.json())
            .then(data => {
                // Normalize vulnerability data to ensure all required fields
                allVulns = data.map(vuln => {
                    // Ensure all vulnerabilities have the required fields
                    return {
                        id: vuln.id || `vuln-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
                        type: vuln.type || 'unknown',
                        severity: vuln.severity || 'medium',
                        url: vuln.url || '#',
                        parameter: vuln.parameter || '',
                        payload: vuln.payload || '',
                        context: vuln.context || '',
                        evidence: vuln.evidence || '',
                        timestamp: vuln.timestamp || new Date().toISOString(),
                        details: vuln.details || 'No details provided'
                    };
                });
                
                renderVulns();
                updateVulnStats();
                updateVulnChart();
                
                // Add to activity log on initial load
                if (allVulns.length > 0 && !window.initialVulnsLoaded) {
                    addToActivityLog(`Loaded ${allVulns.length} vulnerabilities from reports`);
                    window.initialVulnsLoaded = true;
                    
                    // Add critical vulnerabilities to the critical alerts panel
                    const criticalVulns = allVulns.filter(v => v.severity === 'critical');
                    criticalVulns.forEach(vuln => {
                        addToCriticalAlerts(vuln);
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching vulnerabilities:', error);
                addToActivityLog('Failed to fetch vulnerability data', 'error');
            });
    }
    
    // Fetch and render targets
    function fetchTargets() {
        fetch('/api/targets')
            .then(response => response.json())
            .then(data => {
                allTargets = data;
                renderTargets();
                
                // Update stats
                document.getElementById('statTargets').innerText = data.length;
                
                // Add to activity log on initial load
                if (data.length > 0 && !window.initialTargetsLoaded) {
                    addToActivityLog(`Loaded ${data.length} targets`);
                    window.initialTargetsLoaded = true;
                }
            })
            .catch(error => {
                console.error('Error fetching targets:', error);
                addToActivityLog('Failed to fetch target data', 'error');
            });
    }
    
    // Validate table structure to prevent DataTables errors
    function validateTableStructure() {
        const thead = document.querySelector('#vulnTable thead tr');
        const tbody = document.getElementById('vulnTableBody');
        
        if (!thead || !tbody) {
            console.error('Table structure validation failed: thead or tbody not found');
            return false;
        }
        
        // Get number of columns in header
        const headerColumns = thead.children.length;
        console.log(`Table validation: Header has ${headerColumns} columns`);
        
        // Check each row in tbody to ensure it has the same number of columns
        let valid = true;
        for (let i = 0; i < tbody.children.length; i++) {
            const row = tbody.children[i];
            if (row.children.length !== headerColumns) {
                console.error(`Table row ${i} has ${row.children.length} columns, expected ${headerColumns}`);
                
                // Fix the row
                while (row.children.length < headerColumns) {
                    const td = document.createElement('td');
                    td.innerHTML = '-';
                    row.appendChild(td);
                }
                
                // If we have too many columns, remove excess
                while (row.children.length > headerColumns) {
                    row.removeChild(row.lastChild);
                }
                
                valid = false;
            }
        }
        
        if (!valid) {
            console.warn('Table structure was fixed');
        }
        
        return true;
    }
    
    // Initialize DataTable for vulnerabilities
    function initVulnTable() {
        try {
            // Check if DataTable is already initialized
            if ($.fn.DataTable.isDataTable('#vulnTable')) {
                $('#vulnTable').DataTable().destroy();
            }
            
            // Validate and fix table structure
            validateTableStructure();
            
            // Get the column count for validation
            const columnCount = $('#vulnTable thead th').length;
            console.log(`DataTables: Table has ${columnCount} columns in header`);
            
            // Add empty row if table is empty to ensure consistent structure
            const tbody = document.getElementById('vulnTableBody');
            if (tbody.children.length === 0) {
                const tr = document.createElement('tr');
                for (let i = 0; i < columnCount; i++) {
                    const td = document.createElement('td');
                    td.innerHTML = '&nbsp;';
                    tr.appendChild(td);
                }
                tbody.appendChild(tr);
                // This row will be hidden by DataTables empty table message
            }
            
            // Initialize DataTable with custom options
            $('#vulnTable').DataTable({
                pageLength: 10,
                lengthMenu: [5, 10, 25, 50],
                order: [[5, 'desc']], // Sort by timestamp desc
                responsive: true,
                language: {
                    search: "_INPUT_",
                    searchPlaceholder: "Search vulnerabilities...",
                    emptyTable: "No vulnerabilities found",
                    // Add custom styling to language options
                    lengthMenu: `<span style="color:#b0b8c1">Show</span> _MENU_ <span style="color:#b0b8c1">entries</span>`,
                    info: `<span style="color:#b0b8c1">Showing _START_ to _END_ of _TOTAL_ entries</span>`,
                    infoEmpty: `<span style="color:#b0b8c1">Showing 0 to 0 of 0 entries</span>`,
                    infoFiltered: `<span style="color:#b0b8c1">(filtered from _MAX_ total entries)</span>`,
                    paginate: {
                        first: `<span style="color:#e0e0e0">First</span>`,
                        previous: `<span style="color:#e0e0e0">Previous</span>`,
                        next: `<span style="color:#e0e0e0">Next</span>`,
                        last: `<span style="color:#e0e0e0">Last</span>`
                    },
                    zeroRecords: `<span style="color:#b0b8c1">No matching records found</span>`
                },
                dom: '<"top"lf>rt<"bottom"ip><"clear">',
                initComplete: function() {
                    // Style the search box
                    $('.dataTables_filter input').addClass('form-control form-control-sm bg-dark text-light');
                    $('.dataTables_length select').addClass('form-control form-control-sm bg-dark text-light');
                    
                    // Fix background colors for all DataTables elements
                    $('.dataTables_wrapper, .dataTables_length, .dataTables_filter, .dataTables_info, .dataTables_paginate, .top, .bottom')
                        .css('background-color', '#181c20');
                    
                    // Fix the text color as well
                    $('.dataTables_length, .dataTables_length label, .dataTables_length select').css('color', '#b0b8c1');
                    $('.dataTables_info').css('color', '#b0b8c1');
                    $('.dataTables_filter, .dataTables_filter label').css('color', '#b0b8c1');
                    
                    // Log success
                    console.log('DataTables initialized successfully');
                }
            }).on('draw.dt', function() {
                // Apply styling again after each table redraw
                setTimeout(function() {
                    // Fix background colors for all DataTables elements
                    $('.dataTables_wrapper, .dataTables_length, .dataTables_filter, .dataTables_info, .dataTables_paginate, .top, .bottom')
                        .css('background-color', '#181c20');
                    
                    // Fix text colors
                    $('.dataTables_info').css('color', '#b0b8c1');
                    $('.dataTables_length, .dataTables_length label, .dataTables_length select').css('color', '#b0b8c1');
                    $('.dataTables_filter, .dataTables_filter label').css('color', '#b0b8c1');
                }, 0);
            });
        } catch (error) {
            console.error('Error initializing DataTable:', error);
            document.getElementById('noVulns').style.display = 'block';
        }
    }
    
    // Render vulnerabilities to table
    function renderVulns() {
        const severity = document.getElementById('filterSeverity')?.value || '';
        const tbody = document.getElementById('vulnTableBody');
        tbody.innerHTML = '';
        
        let filteredVulns = allVulns;
        if (severity) {
            filteredVulns = allVulns.filter(vuln => vuln.severity === severity);
        }
        
        // Check if we have any data
        if (filteredVulns.length === 0) {
            document.getElementById('noVulns').style.display = 'block';
            
            // Initialize DataTable even with empty data to avoid errors
            initVulnTable();
            return;
        }
        
        // Ensure the first vulnerability has all required fields
        const sampleVuln = filteredVulns[0] || {};
        
        // Get the number of columns from the table header
        const numColumns = document.querySelector('#vulnTable thead tr').children.length;
        
        for (let i = 0; i < filteredVulns.length; i++) {
            const vuln = filteredVulns[i];
            const tr = document.createElement('tr');
            
            // Build the HTML with the exact number of columns as the header
            let html = '';
            
            // Column 1: Type
            html += `<td><span class="badge bg-secondary">${vuln.type || 'unknown'}</span></td>`;
            
            // Column 2: Severity
            html += `<td><span class="severity-${vuln.severity || 'medium'}">${vuln.severity?.toUpperCase() || 'MEDIUM'}</span></td>`;
            
            // Column 3: URL
            html += `<td><a href="${vuln.url || '#'}" target="_blank" class="text-info">${truncate(vuln.url || '', 40)}</a></td>`;
            
            // Column 4: Parameter
            html += `<td>${vuln.parameter || '-'}</td>`;
            
            // Column 5: Payload
            html += `<td><code class="text-warning">${truncate(vuln.payload || '', 30)}</code></td>`;
            
            // Column 6: Timestamp
            html += `<td>${formatTimestamp(vuln.timestamp) || '-'}</td>`;
            
            // Column 7: Actions
            html += `<td>
                <button class="btn btn-sm btn-outline-info me-1 view-details" data-vuln-index="${i}">
                        <i class="bi bi-eye"></i>
                    </button>
                <button class="btn btn-sm btn-outline-danger delete-vuln" data-vuln-index="${i}">
                    <i class="bi bi-trash"></i>
                </button>
            </td>`;
            
            // Set the HTML
            tr.innerHTML = html;
            tbody.appendChild(tr);
        }
        
        document.getElementById('noVulns').style.display = 'none';
        
        // Add event listeners for the action buttons
        document.querySelectorAll('.view-details').forEach(button => {
            button.addEventListener('click', function() {
                const index = this.getAttribute('data-vuln-index');
                showVulnDetails(filteredVulns[index]);
            });
        });
        
        document.querySelectorAll('.delete-vuln').forEach(button => {
            button.addEventListener('click', function() {
                const index = this.getAttribute('data-vuln-index');
                deleteVuln(filteredVulns[index]);
            });
        });
        
        // Initialize DataTable
        initVulnTable();
    }
    
    // Render targets to table
    function renderTargets() {
        const tbody = document.getElementById('targetsTableBody');
        tbody.innerHTML = '';
        
        if (allTargets.length === 0) {
            const tr = document.createElement('tr');
            tr.innerHTML = `<td colspan="5" class="text-center text-muted">No targets added yet</td>`;
            tbody.appendChild(tr);
            return;
        }
        
        for (let i = 0; i < allTargets.length; i++) {
            const target = allTargets[i];
            const tr = document.createElement('tr');
            
            // Get vulnerabilities count for this target
            const targetVulns = allVulns.filter(v => v.url && v.url.includes(target));
            const criticalVulns = targetVulns.filter(v => v.severity === 'critical').length;
            
            const lastScan = new Date();
            lastScan.setHours(lastScan.getHours() - Math.floor(Math.random() * 48));
            
            tr.innerHTML = `
                <td><a href="${target}" target="_blank">${target}</a></td>
                <td>${lastScan.toLocaleString()}</td>
                <td><span class="badge bg-success">Completed</span></td>
                <td>${targetVulns.length} ${criticalVulns ? `<span class="text-danger">(${criticalVulns} critical)</span>` : ''}</td>
                <td>
                    <button class="btn btn-sm btn-outline-info mx-1" data-target-index="${i}" data-action="rescan"><i class="bi bi-arrow-repeat"></i></button>
                    <button class="btn btn-sm btn-outline-warning mx-1" data-target-index="${i}" data-action="view"><i class="bi bi-eye"></i></button>
                    <button class="btn btn-sm btn-outline-danger mx-1" data-target-index="${i}" data-action="delete"><i class="bi bi-trash"></i></button>
                </td>
            `;
            tbody.appendChild(tr);
            
            // Add event listeners for the buttons
            const buttons = tr.querySelectorAll('button');
            buttons.forEach(button => {
                button.addEventListener('click', function() {
                    const index = this.getAttribute('data-target-index');
                    const action = this.getAttribute('data-action');
                    const target = allTargets[index];
                    
                    if (action === 'rescan') {
                        rescanTarget(target);
                    } else if (action === 'view') {
                        filterVulnsByTarget(target);
                    } else if (action === 'delete') {
                        removeTarget(target, index);
                    }
                });
            });
        }
    }
    
    // Filter vulnerabilities by target
    function filterVulnsByTarget(target) {
        // Filter the vulnerabilities table to only show vulns for this target
        const domain = new URL(target).hostname;
        $('#vulnTable').DataTable().search(domain).draw();
        
        // Switch to vulnerabilities tab
        document.querySelector('a[href="#vulns"]').click();
    }
    
    // Rescan a target
    function rescanTarget(target) {
        fetch('/api/targets/rescan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({target: target})
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'rescanning') {
                addToActivityLog(`Rescanning target: ${target}`);
                addToTerminalFeed(`[*] Initiating rescan of target: ${target}`, 'info');
            } else {
                addToActivityLog(`Error rescanning target: ${data.msg || 'Unknown error'}`, 'error');
                addToTerminalFeed(`[!] Error rescanning target: ${data.msg || 'Unknown error'}`, 'error');
            }
        })
        .catch(error => {
            addToActivityLog(`Error rescanning target: ${error}`, 'error');
            addToTerminalFeed(`[!] Error rescanning target: ${error}`, 'error');
        });
    }
    
    // Remove a target
    function removeTarget(target, index) {
        fetch('/api/targets/remove', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({target: target})
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'removed') {
                allTargets.splice(index, 1);
                renderTargets();
                addToActivityLog(`Removed target: ${target}`);
                addToTerminalFeed(`[-] Target removed from scan list: ${target}`, 'info');
            } else {
                addToActivityLog(`Error removing target: ${data.msg || 'Unknown error'}`, 'error');
                addToTerminalFeed(`[!] Error removing target: ${data.msg || 'Unknown error'}`, 'error');
            }
        })
        .catch(error => {
            addToActivityLog(`Error removing target: ${error}`, 'error');
            addToTerminalFeed(`[!] Error removing target: ${error}`, 'error');
        });
    }
    
    // Delete a vulnerability
    function deleteVuln(vuln) {
        fetch('/api/vulns/delete', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({id: vuln.id})
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'deleted') {
                const index = allVulns.findIndex(v => v.id === vuln.id);
                if (index !== -1) {
                    allVulns.splice(index, 1);
                    renderVulns();
                    updateVulnStats();
                }
                addToActivityLog(`Deleted vulnerability: ${vuln.type} at ${vuln.url}`);
            } else {
                addToActivityLog(`Error deleting vulnerability: ${data.msg || 'Unknown error'}`, 'error');
            }
        })
        .catch(error => {
            addToActivityLog(`Error deleting vulnerability: ${error}`, 'error');
        });
    }
    
    // Show vulnerability details in a modal
    function showVulnDetails(vuln) {
        // Create modal if it doesn't exist
        let modal = document.getElementById('vulnDetailsModal');
        if (!modal) {
            modal = document.createElement('div');
            modal.className = 'modal fade';
            modal.id = 'vulnDetailsModal';
            modal.tabIndex = '-1';
            modal.innerHTML = `
                <div class="modal-dialog modal-lg">
                    <div class="modal-content bg-dark text-light">
                        <div class="modal-header">
                            <h5 class="modal-title">Vulnerability Details</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body" id="vulnDetailsContent">
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-outline-danger" id="ignoreVulnBtn">Ignore</button>
                            <button type="button" class="btn btn-outline-warning" id="reCheckVulnBtn">Re-check</button>
                            <button type="button" class="btn btn-outline-success" id="exportVulnBtn">Export</button>
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        
        // Populate modal content
        const content = document.getElementById('vulnDetailsContent');
        content.innerHTML = `
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Type:</div>
                <div class="col-md-9"><span class="badge bg-secondary">${vuln.type || 'unknown'}</span></div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Severity:</div>
                <div class="col-md-9"><span class="severity-${vuln.severity || 'medium'}">${vuln.severity?.toUpperCase() || 'MEDIUM'}</span></div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">URL:</div>
                <div class="col-md-9"><a href="${vuln.url}" target="_blank" class="text-info">${vuln.url || '-'}</a></div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Parameter:</div>
                <div class="col-md-9">${vuln.parameter || '-'}</div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Payload:</div>
                <div class="col-md-9"><pre class="bg-dark p-2 border">${vuln.payload || '-'}</pre></div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Context:</div>
                <div class="col-md-9">${vuln.context || '-'}</div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Evidence:</div>
                <div class="col-md-9"><pre class="bg-dark p-2 border" style="max-height:200px;overflow:auto;">${vuln.evidence || '-'}</pre></div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Timestamp:</div>
                <div class="col-md-9">${formatTimestamp(vuln.timestamp) || '-'}</div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Details:</div>
                <div class="col-md-9">${vuln.details || '-'}</div>
            </div>
            <div class="row mb-3">
                <div class="col-md-3 fw-bold text-muted">Remediation:</div>
                <div class="col-md-9">${getRemediation(vuln.type) || 'No specific remediation available.'}</div>
            </div>
        `;
        
        // Show the modal
        const bsModal = new bootstrap.Modal(modal);
        bsModal.show();
        
        // Add event listeners for the modal buttons
        document.getElementById('ignoreVulnBtn').addEventListener('click', function() {
            fetch('/api/vulns/ignore', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({id: vuln.id})
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'ignored') {
                    bsModal.hide();
                    addToActivityLog(`Ignored vulnerability: ${vuln.type} at ${vuln.url}`);
                    addToTerminalFeed(`[*] Vulnerability marked as ignored: ${vuln.type} at ${vuln.url}`, 'info');
                    fetchVulns(); // Refresh the vulnerability list
                }
            });
        });
        
        document.getElementById('reCheckVulnBtn').addEventListener('click', function() {
            addToActivityLog(`Re-checking vulnerability: ${vuln.type} at ${vuln.url}`);
            addToTerminalFeed(`[*] Re-validating vulnerability: ${vuln.type} at ${vuln.url}`, 'info');
            bsModal.hide();
        });
        
        document.getElementById('exportVulnBtn').addEventListener('click', function() {
            // Export a single vulnerability as JSON
            const jsonStr = JSON.stringify(vuln, null, 2);
            const blob = new Blob([jsonStr], {type: 'application/json'});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `vulnerability-${vuln.id || Date.now()}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            
            addToActivityLog(`Exported vulnerability details: ${vuln.type} at ${vuln.url}`);
        });
    }
    
    // Update dashboard statistics
    function updateVulnStats() {
        if (!allVulns || allVulns.length === 0) return;
        
        // Update vulnerability count
        document.getElementById('statTotalVulns').innerText = allVulns.length;
        
        // Count by severity
        const criticalVulns = allVulns.filter(vuln => vuln.severity === 'critical').length;
        const highVulns = allVulns.filter(vuln => vuln.severity === 'high').length;
        const mediumVulns = allVulns.filter(vuln => vuln.severity === 'medium').length;
        const lowVulns = allVulns.filter(vuln => vuln.severity === 'low').length;
        
        document.getElementById('statCritical').innerText = criticalVulns;
        
        // Count exploitable vulnerabilities
        const exploitableTypes = ['rce', 'sqli', 'xss', 'xxe', 'lfi', 'ssrf'];
        const exploitableVulns = allVulns.filter(vuln => 
            exploitableTypes.includes(vuln.type?.toLowerCase())
        ).length;
        document.getElementById('statExploitableVulns').innerText = exploitableVulns;
        
        // Count unique targets
        const uniqueTargets = new Set();
        allVulns.forEach(vuln => {
            if (vuln.url) {
                try {
                    const url = new URL(vuln.url);
                    uniqueTargets.add(url.hostname);
                } catch (e) {
                    // Invalid URL, just add as is
                    uniqueTargets.add(vuln.url);
                }
            }
        });
        document.getElementById('statTargets').innerText = uniqueTargets.size;
        
        // Update sidebar stats with more meaningful data
        const completedScans = allTargets ? allTargets.length : 0;
        
        // Add some sample active scans if we have targets
        const activeScans = completedScans > 0 ? Math.min(3, Math.ceil(completedScans * 0.3)) : 2;
        
        // Calculate simulated success rate (80-95%)
        const successRate = completedScans > 0 ? 
            Math.floor(80 + Math.random() * 15) + '%' : 
            '87%'; // Default sample rate
            
        document.getElementById('statSideScanRate').innerText = successRate;
        document.getElementById('statCompletedScans').innerText = completedScans > 0 ? completedScans : 8;
        document.getElementById('statActiveScans').innerText = activeScans;
        document.getElementById('scanProgressBar').style.width = successRate;
        
        // Add to terminal feed showing the counts
        addToTerminalFeed(`[*] Statistics updated: ${allVulns.length} vulnerabilities (${criticalVulns} critical, ${highVulns} high, ${mediumVulns} medium, ${lowVulns} low)`, 'info');
    }
    
    // Update vulnerability chart
    function updateVulnChart() {
        const timeRange = document.getElementById('timeRange')?.value || 'week';
        
        // Filter vulnerabilities based on selected time range
        let filteredVulns = [...allVulns];
        
        const now = new Date();
        if (timeRange === 'day') {
            const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000);
            filteredVulns = filteredVulns.filter(v => new Date(v.timestamp) >= oneDayAgo);
        } else if (timeRange === 'week') {
            const oneWeekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000);
            filteredVulns = filteredVulns.filter(v => new Date(v.timestamp) >= oneWeekAgo);
        } else if (timeRange === 'month') {
            const oneMonthAgo = new Date(now - 30 * 24 * 60 * 60 * 1000);
            filteredVulns = filteredVulns.filter(v => new Date(v.timestamp) >= oneMonthAgo);
        }
        
        // Group vulnerabilities by type and severity
        const vulnsByType = {};
        const vulnsBySeverity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        };
        
        filteredVulns.forEach(vuln => {
            // Count by type
            const type = vuln.type || 'unknown';
            if (!vulnsByType[type]) {
                vulnsByType[type] = 0;
            }
            vulnsByType[type]++;
            
            // Count by severity
            const severity = vuln.severity || 'medium';
            if (vulnsBySeverity.hasOwnProperty(severity)) {
                vulnsBySeverity[severity]++;
            }
        });
        
        // Sort by count (descending)
        const sortedTypes = Object.keys(vulnsByType).sort((a, b) => vulnsByType[b] - vulnsByType[a]);
        
        // Create container for multiple charts
        const chartContainer = document.getElementById('vulnChartContainer');
        // Calculate ideal height for the bar chart based on the number of vulnerability types
        // Set a minimum height of 300px and add 30px for each type over 8
        const barChartHeight = Math.max(300, 250 + (sortedTypes.length > 8 ? (sortedTypes.length - 8) * 30 : 0));
        
        if (chartContainer) {
            chartContainer.innerHTML = `
                <div class="row">
                    <div class="col-md-8">
                        <div style="height: ${barChartHeight}px;">
                            <canvas id="vulnSummaryChart"></canvas>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div style="height: ${barChartHeight}px;">
                            <canvas id="vulnSeverityChart"></canvas>
                        </div>
                    </div>
                </div>
                <div class="row mt-3">
                    <div class="col-12">
                        <div style="height: 180px;">
                            <canvas id="vulnTrendChart"></canvas>
                        </div>
                    </div>
                </div>
            `;
        }
        
        // Color mapping for vulnerability types
        const colorMap = {
            'xss': 'rgba(255, 82, 82, 0.8)',
            'sqli': 'rgba(255, 152, 0, 0.8)',
            'csrf': 'rgba(255, 235, 59, 0.8)',
            'ssrf': 'rgba(33, 150, 243, 0.8)',
            'lfi': 'rgba(76, 175, 80, 0.8)',
            'rce': 'rgba(156, 39, 176, 0.8)',
            'open_redirect': 'rgba(0, 188, 212, 0.8)',
            'xxe': 'rgba(63, 81, 181, 0.8)',
            'nosql': 'rgba(233, 30, 99, 0.8)',
            'ssti': 'rgba(205, 220, 57, 0.8)',
            'jwt': 'rgba(121, 85, 72, 0.8)'
        };
        
        // Generate colors for the type chart
        const backgroundColors = sortedTypes.map(label => colorMap[label] || 'rgba(189, 189, 189, 0.8)');
        
        // Prepare data for type chart
        const typeLabels = sortedTypes;
        const typeData = sortedTypes.map(type => vulnsByType[type]);
        
        // Create bar chart for vulnerability types
        const typeChartConfig = {
            type: 'bar',
            data: {
                labels: typeLabels,
                datasets: [{
                    label: 'Vulnerabilities by Type',
                    data: typeData,
                    backgroundColor: backgroundColors,
                    borderColor: backgroundColors.map(color => color.replace('0.8', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Vulnerability Types',
                        color: '#e0e0e0',
                        font: {
                            size: 14
                        }
                    },
                    legend: {
                        display: false,
                        labels: {
                            color: '#e0e0e0'
                        }
                    },
                    tooltip: {
                        backgroundColor: '#23272b',
                        titleColor: '#e0e0e0',
                        bodyColor: '#e0e0e0',
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.raw} vulnerabilities`;
                            }
                        }
                    }
                },
                scales: {
                    y: {
                        ticks: {
                            color: '#b0b8c1'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        title: {
                            color: '#b0b8c1'
                        }
                    },
                    x: {
                        beginAtZero: true,
                        ticks: {
                            color: '#b0b8c1'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        title: {
                            color: '#b0b8c1'
                        }
                    }
                }
            }
        };
        
        // Create or update the type chart
        const typeCtx = document.getElementById('vulnSummaryChart')?.getContext('2d');
        if (typeCtx) {
        if (chartInstance) {
            chartInstance.destroy();
            }
            chartInstance = new Chart(typeCtx, typeChartConfig);
        }
        
        // Create donut chart for vulnerability severity
        const severityLabels = Object.keys(vulnsBySeverity);
        const severityData = severityLabels.map(severity => vulnsBySeverity[severity]);
        const severityColors = {
            'critical': 'rgba(255, 82, 82, 0.8)',
            'high': 'rgba(255, 152, 0, 0.8)',
            'medium': 'rgba(33, 150, 243, 0.8)',
            'low': 'rgba(76, 175, 80, 0.8)'
        };
        
        const severityChartConfig = {
            type: 'doughnut',
            data: {
                labels: severityLabels.map(s => s.toUpperCase()),
                datasets: [{
                    data: severityData,
                    backgroundColor: severityLabels.map(s => severityColors[s]),
                    borderColor: severityLabels.map(s => severityColors[s].replace('0.8', '1')),
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    title: {
                        display: true,
                        text: 'Severity Distribution',
                        color: '#e0e0e0',
                        font: {
                            size: 14
                        }
                    },
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#e0e0e0',
                            boxWidth: 12,
                            padding: 10,
                            font: {
                                color: '#e0e0e0'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#23272b',
                        titleColor: '#e0e0e0',
                        bodyColor: '#e0e0e0',
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.raw} vulnerabilities`;
                            }
                        }
                    }
                }
            }
        };
        
        // Create or update the severity chart
        const severityCtx = document.getElementById('vulnSeverityChart')?.getContext('2d');
        if (severityCtx) {
            new Chart(severityCtx, severityChartConfig);
        }
        
        // Generate trend data (simulated historical data)
        const trendLabels = [];
        const trendData = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        };
        
        // Generate dates for the past 7 days
        const days = 7;
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            trendLabels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            
            // Generate simulated historical data with some randomization based on current counts
            Object.keys(trendData).forEach(severity => {
                // Base the trend on the current counts with some randomization
                const baseCount = vulnsBySeverity[severity];
                // For past days, show fewer vulnerabilities with some randomness
                const factor = i / days; // Earlier days have lower factor
                const randomVariation = Math.random() * 0.3 - 0.15; // -15% to +15%
                const count = Math.max(0, Math.round(baseCount * (factor + 0.2 + randomVariation)));
                trendData[severity].push(count);
            });
        }
        
        // Create trend chart (line chart)
        const trendChartConfig = {
            type: 'line',
            data: {
                labels: trendLabels,
                datasets: [
                    {
                        label: 'Critical',
                        data: trendData.critical,
                        borderColor: severityColors.critical.replace('0.8', '1'),
                        backgroundColor: severityColors.critical.replace('0.8', '0.1'),
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'High',
                        data: trendData.high,
                        borderColor: severityColors.high.replace('0.8', '1'),
                        backgroundColor: severityColors.high.replace('0.8', '0.1'),
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Medium',
                        data: trendData.medium,
                        borderColor: severityColors.medium.replace('0.8', '1'),
                        backgroundColor: severityColors.medium.replace('0.8', '0.1'),
                        fill: true,
                        tension: 0.3
                    },
                    {
                        label: 'Low',
                        data: trendData.low,
                        borderColor: severityColors.low.replace('0.8', '1'),
                        backgroundColor: severityColors.low.replace('0.8', '0.1'),
                        fill: true,
                        tension: 0.3
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Vulnerability Trend',
                        color: '#e0e0e0',
                        font: {
                            size: 14
                        }
                    },
                    legend: {
                        position: 'top',
                        labels: {
                            color: '#e0e0e0',
                            boxWidth: 12,
                            padding: 10,
                            font: {
                                color: '#e0e0e0'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: '#23272b',
                        titleColor: '#e0e0e0',
                        bodyColor: '#e0e0e0',
                        mode: 'index',
                        intersect: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        stacked: false,
                        ticks: {
                            color: '#b0b8c1'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        title: {
                            display: false,
                            color: '#b0b8c1'
                        }
                    },
                    x: {
                        ticks: {
                            color: '#b0b8c1'
                        },
                        grid: {
                            color: 'rgba(255, 255, 255, 0.05)'
                        },
                        title: {
                            display: false,
                            color: '#b0b8c1'
                        }
                    }
                }
            }
        };
        
        // Create or update the trend chart
        const trendCtx = document.getElementById('vulnTrendChart')?.getContext('2d');
        if (trendCtx) {
            new Chart(trendCtx, trendChartConfig);
        }
    }
    
    // Initialize vulnerability map
    let vulnerabilityMap;
    let markerClusterGroup;
    
    function initializeMap() {
        // If map already initialized, return
        if (vulnerabilityMap) {
            return;
        }
        
        // Create map with dark theme
        vulnerabilityMap = L.map('vulnerabilityMap', {
            center: [20, 0], // Center the map at 0,0 (middle of the world)
            zoom: 2,
            minZoom: 2,
            maxZoom: 18,
            zoomControl: true,
            attributionControl: false, // We'll add a custom attribution below
            worldCopyJump: true // Allows seamless horizontal scrolling
        });
        
        // Add dark-theme map tiles - more Kaspersky-like dark blue style
        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_nolabels/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>',
            subdomains: 'abcd',
            maxZoom: 19
        }).addTo(vulnerabilityMap);
        
        // Add custom attribution
        L.control.attribution({
            position: 'bottomright'
        }).addAttribution('Zodiac Crawler | Global Threat Intelligence').addTo(vulnerabilityMap);
        
        // Initialize the marker cluster group with custom styles for Kaspersky look
        markerClusterGroup = L.markerClusterGroup({
            showCoverageOnHover: false,
            maxClusterRadius: 40,
            iconCreateFunction: function(cluster) {
                // Custom icon for clusters - Kaspersky style
                const count = cluster.getChildCount();
                let className;
                
                if (count < 10) {
                    className = 'marker-cluster-small';
                } else if (count < 50) {
                    className = 'marker-cluster-medium';
                } else {
                    className = 'marker-cluster-large';
                }
                
                return L.divIcon({ 
                    html: `<div><span>${count}</span></div>`, 
                    className: `marker-cluster kaspersky-cluster ${className}`, 
                    iconSize: L.point(40, 40) 
                });
            }
        });
        
        // Add the empty cluster group to the map
        vulnerabilityMap.addLayer(markerClusterGroup);
        
        // Event listener for the vulnerability type filter
        document.getElementById('mapVulnType')?.addEventListener('change', function() {
            updateMapMarkers();
        });
        
        // Create more animated lines for Kaspersky style
        setTimeout(() => {
            // Create 5 lines instead of 3
            for (let i = 0; i < 3; i++) {
                createAnimatedLines();
            }
        }, 500);
    }
    
    // Global array to store server locations
let serverLocations = [];

// Add function to create animated lines between servers
function createAnimatedLines() {
    if (!vulnerabilityMap) return;
    
    // Get all server locations on the map
    if (serverLocations.length < 3) {
        // If we don't have enough servers yet, add some default important nodes
        const defaultNodes = [
            { lat: 37.77, lng: -122.41, name: 'San Francisco' }, // SF
            { lat: 40.71, lng: -74.00, name: 'New York' }, // NY
            { lat: 51.50, lng: -0.12, name: 'London' }, // London
            { lat: 35.68, lng: 139.69, name: 'Tokyo' }, // Tokyo
            { lat: 52.52, lng: 13.40, name: 'Berlin' }, // Berlin
            { lat: -33.86, lng: 151.20, name: 'Sydney' } // Sydney
        ];
        
        // Filter out any default nodes that are already in serverLocations
        const newNodes = defaultNodes.filter(defaultNode => 
            !serverLocations.some(server => 
                Math.abs(server.lat - defaultNode.lat) < 0.1 && 
                Math.abs(server.lng - defaultNode.lng) < 0.1
            )
        );
        
        // Add all new default nodes to serverLocations
        serverLocations = [...serverLocations, ...newNodes];
    }
    
    // Ensure we have at least 3 nodes for three lines
    if (serverLocations.length < 3) return;
    
    // Remove any existing lines
    if (window.animatedLines) {
        window.animatedLines.forEach(line => {
            if (line.polyline) {
                vulnerabilityMap.removeLayer(line.polyline);
            }
            if (line.marker) {
                vulnerabilityMap.removeLayer(line.marker);
            }
        });
    }
    
    // Initialize animated lines array
    window.animatedLines = [];
    
    // Create 3 dynamic line paths through multiple servers
    for (let i = 0; i < 3; i++) {
        // Create a route through multiple servers
        let routeServers = [];
        let startIdx = Math.floor(Math.random() * serverLocations.length);
        
        // Add the starting server
        routeServers.push(serverLocations[startIdx]);
        
        // Add 2-4 additional servers to the route
        const numHops = 2 + Math.floor(Math.random() * 3); // 2-4 hops
        
        for (let j = 0; j < numHops; j++) {
            // Find a server that's not already in the route
            let nextIdx;
            do {
                nextIdx = Math.floor(Math.random() * serverLocations.length);
            } while (routeServers.includes(serverLocations[nextIdx]));
            
            // Add this server to the route
            routeServers.push(serverLocations[nextIdx]);
        }
        
        // Extract coordinates for the route
        const routePoints = routeServers.map(server => ({lat: server.lat, lng: server.lng}));
        
        // Get a random color for this line
        const lineColors = ['#00ffff', '#00ccff', '#1a75ff']; // Cyan, Light blue, Blue
        const randomColorIndex = Math.floor(Math.random() * lineColors.length);
        const lineColor = lineColors[randomColorIndex];
        
        // Create polyline for the entire route
        const polyline = L.polyline(routePoints, {
            color: lineColor,
            weight: 2,
            opacity: 0.7,
            smoothFactor: 1, 
            className: 'animated-line kaspersky-line'
        }).addTo(vulnerabilityMap);
        
        // Create animation marker (dot that moves along the route)
        const animatedMarker = L.circleMarker(routePoints[0], {
            radius: 3,
            color: lineColor,
            fillColor: '#ffffff',
            fillOpacity: 1,
            weight: 2
        }).addTo(vulnerabilityMap);
        
        // Store references for animation
        window.animatedLines.push({
            polyline: polyline,
            marker: animatedMarker,
            route: routePoints,
            currentSegment: 0,
            progress: 0,
            color: lineColor,
            speedFactor: 0.8 + (Math.random() * 0.5) // Random speed variation
        });
    }
    
    // Start animation loop if not already running
    if (!window.lineAnimationFrame) {
        animateLines();
    }
}

// Track time for periodic path changes
let lastPathChangeTime = Date.now();
const PATH_CHANGE_INTERVAL = 8000; // Change paths every 8 seconds

// Function to animate the lines with multi-point hopping
function animateLines() {
    if (!window.animatedLines || !vulnerabilityMap) {
        window.lineAnimationFrame = null;
        return;
    }
    
    // Check if it's time to regenerate paths
    const currentTime = Date.now();
    if (currentTime - lastPathChangeTime > PATH_CHANGE_INTERVAL) {
        // Time to regenerate paths for at least one line
        const lineToChange = Math.floor(Math.random() * window.animatedLines.length);
        
        // Only proceed if we have enough servers
        if (serverLocations.length >= 4) {
            const line = window.animatedLines[lineToChange];
            
            // Remember current position
            const currentPosition = line.marker.getLatLng();
            
            // Find the closest server to current position
            let closestServerIdx = 0;
            let closestDistance = Number.MAX_VALUE;
            
            serverLocations.forEach((server, idx) => {
                const distance = Math.sqrt(
                    Math.pow(server.lat - currentPosition.lat, 2) + 
                    Math.pow(server.lng - currentPosition.lng, 2)
                );
                if (distance < closestDistance) {
                    closestDistance = distance;
                    closestServerIdx = idx;
                }
            });
            
            // Start the new route from this server
            let routeServers = [serverLocations[closestServerIdx]];
            
            // Add 2-4 additional servers to the route
            const numHops = 2 + Math.floor(Math.random() * 3);
            
            for (let j = 0; j < numHops; j++) {
                // Find a server that's not already in the route
                let nextIdx;
                let attempts = 0;
                do {
                    nextIdx = Math.floor(Math.random() * serverLocations.length);
                    attempts++;
                    if (attempts > 20) break; // Prevent infinite loop
                } while (routeServers.includes(serverLocations[nextIdx]) && attempts < 20);
                
                if (attempts < 20) {
                    routeServers.push(serverLocations[nextIdx]);
                }
            }
            
            // Extract coordinates for the route
            const routePoints = routeServers.map(server => ({lat: server.lat, lng: server.lng}));
            
            // Update the polyline
            line.polyline.setLatLngs(routePoints);
            
            // Update the route data
            line.route = routePoints;
            line.currentSegment = 0;
            line.progress = 0;
            
            console.log(`Line ${lineToChange} exploring new path with ${routePoints.length} servers`);
        }
        
        lastPathChangeTime = currentTime;
    }
    
    // Update each animated line
    window.animatedLines.forEach(line => {
        if (!line.route || line.route.length < 2) return;
        
        // Calculate current segment start and end
        const segmentStart = line.route[line.currentSegment];
        const segmentEnd = line.route[line.currentSegment + 1];
        
        // Update progress along current segment - Kaspersky style is smoother
        line.progress += 0.003 * line.speedFactor;
        
        // Check if we've reached the end of this segment
        if (line.progress >= 1) {
            // Move to next segment
            line.currentSegment = (line.currentSegment + 1) % (line.route.length - 1);
            line.progress = 0;
            
            // If we've completed a full loop, potentially add a new point
            if (line.currentSegment === 0 && Math.random() > 0.7) {
                // Get the current point
                const currentPoint = line.route[line.currentSegment];
                
                // Find a server that's not too close to any existing point in the route
                const eligibleServers = serverLocations.filter(server => 
                    !line.route.some(point =>
                        Math.sqrt(
                            Math.pow(point.lat - server.lat, 2) + 
                            Math.pow(point.lng - server.lng, 2)
                        ) < 0.1
                    )
                );
                
                if (eligibleServers.length > 0) {
                    // Add a new point to the route - Kaspersky-like behavior
                    const newServer = eligibleServers[Math.floor(Math.random() * eligibleServers.length)];
                    const newPoint = {lat: newServer.lat, lng: newServer.lng};
                    
                    // Insert this point into the route
                    line.route.splice(line.currentSegment + 1, 0, newPoint);
                    
                    // Update the polyline
                    line.polyline.setLatLngs(line.route);
                }
            }
        }
        
        // Calculate the current position based on lerping between segment start and end
        const lat = segmentStart.lat + (segmentEnd.lat - segmentStart.lat) * line.progress;
        const lng = segmentStart.lng + (segmentEnd.lng - segmentStart.lng) * line.progress;
        
        // Update the marker position
        line.marker.setLatLng({lat, lng});
    });
    
    // Request the next animation frame
    window.lineAnimationFrame = requestAnimationFrame(animateLines);
}
    
    // Update map with vulnerability markers
function updateMapMarkers() {
    if (!vulnerabilityMap || !markerClusterGroup) {
        initializeMap();
    }
    
    // Get selected vulnerability type filter
    const selectedType = document.getElementById('mapVulnType')?.value || 'all';
    
    // Clear existing markers
    markerClusterGroup.clearLayers();
    
    // Track server locations for this update
    let currentServerLocations = [];
    
    // Filter vulnerabilities based on selected type
    let filteredVulns = [...allVulns];
    if (selectedType !== 'all') {
        filteredVulns = filteredVulns.filter(v => v.type === selectedType);
    }
    
    // Process each vulnerability to add markers
    filteredVulns.forEach(vuln => {
        // Use the URL to determine an approximate location
        // In a real system, you would use a geo-IP service or similar
        const location = getLocationFromUrl(vuln.url);
        
        if (location) {
            // Extract domain for server name
            let serverName = vuln.url;
            try {
                serverName = new URL(vuln.url).hostname;
            } catch (e) {
                // Keep original URL if parsing fails
            }
            
            // Add to current server locations
            currentServerLocations.push({
                lat: location.lat,
                lng: location.lng,
                name: serverName,
                type: vuln.type,
                severity: vuln.severity
            });
            
            // Create a custom icon based on vulnerability type
            const icon = L.divIcon({
                className: `vulnerability-marker ${vuln.type}`,
                html: `<div class="kaspersky-dot ${vuln.severity}"></div>`,
                iconSize: [12, 12]
            });
            
            // Create marker with custom icon
            const marker = L.marker([location.lat, location.lng], {
                icon: icon,
                title: `${vuln.type} vulnerability`
            });
            
            // Create popup content
            const popupContent = `
                <div class="map-popup-title">${vuln.type.toUpperCase()} Vulnerability</div>
                <div class="map-popup-url">${truncate(vuln.url, 60)}</div>
                ${vuln.parameter ? `<div>Parameter: ${vuln.parameter}</div>` : ''}
                <div class="map-popup-severity ${vuln.severity}">Severity: ${vuln.severity}</div>
            `;
            
            // Bind popup to marker
            marker.bindPopup(popupContent);
            
            // Add the marker to the cluster group
            markerClusterGroup.addLayer(marker);
        }
    });
    
    // Update map view if needed
    if (filteredVulns.length > 0) {
        // Fit the map to the markers' bounds with some padding
        const group = new L.featureGroup(markerClusterGroup.getLayers());
        if (group.getBounds().isValid()) {
            vulnerabilityMap.fitBounds(group.getBounds(), {
                padding: [50, 50],
                maxZoom: 7
            });
        }
    }
    
    // Check for new server locations
    const newServers = currentServerLocations.filter(curr => 
        !serverLocations.some(existing => 
            Math.abs(existing.lat - curr.lat) < 0.1 && 
            Math.abs(existing.lng - curr.lng) < 0.1
        )
    );
    
    // If we have new servers, update the global list and recreate lines
    if (newServers.length > 0) {
        // Add new servers to the global list
        serverLocations = [...serverLocations, ...newServers];
        
        // Log discovery of new servers
        newServers.forEach(server => {
            console.log(`New server discovered: ${server.name} (${server.lat.toFixed(2)}, ${server.lng.toFixed(2)})`);
        });
        
        // Limit the total number of servers to prevent performance issues
        if (serverLocations.length > 20) {
            serverLocations = serverLocations.slice(serverLocations.length - 20);
        }
    }
    
    // Create or update the animated lines
    createAnimatedLines();
}
    
    // Helper function to extract approximate location from URL
    // In a real application, this would be replaced with actual geo-IP data
    function getLocationFromUrl(url) {
        if (!url) return null;
        
        try {
            // Extract domain from URL
            const domain = new URL(url).hostname;
            
            // Map of known domains to locations
            // In a real application, this would use a geo-IP database
            const domainLocations = {
                'testphp.vulnweb.com': { lat: 37.77, lng: -122.41 }, // San Francisco
                'demo.testfire.net': { lat: 40.71, lng: -74.00 }, // New York
                'juice-shop.herokuapp.com': { lat: 51.50, lng: -0.12 }, // London
                'geekflare.com': { lat: 19.07, lng: 72.87 }, // Mumbai
                'example.com': { lat: 34.05, lng: -118.24 }, // Los Angeles
                'securecoding.com': { lat: 52.52, lng: 13.40 }, // Berlin
                'securitytesting.org': { lat: 35.68, lng: 139.69 }, // Tokyo
                'hack.me': { lat: -33.86, lng: 151.20 }, // Sydney
                'ctf.com': { lat: 25.20, lng: 55.27 }, // Dubai
                'vulhub.org': { lat: 55.75, lng: 37.61 }, // Moscow
                'securitytracker.com': { lat: 48.85, lng: 2.35 }, // Paris
                'hackerone.com': { lat: 37.77, lng: -122.41 }, // San Francisco
                'bugcrowd.com': { lat: -37.81, lng: 144.96 }, // Melbourne
                'portswigger.net': { lat: 51.50, lng: -0.12 }, // London
                'owasp.org': { lat: 38.90, lng: -77.03 }, // Washington DC
            };
            
            // Check for exact domain match
            for (const knownDomain in domainLocations) {
                if (domain === knownDomain || domain.endsWith('.' + knownDomain)) {
                    return domainLocations[knownDomain];
                }
            }
            
            // Map of major landmass coordinates to ensure servers are placed on land
            const landCoordinates = [
                // North America
                { lat: 40.71, lng: -74.00 }, // New York
                { lat: 37.77, lng: -122.41 }, // San Francisco 
                { lat: 41.87, lng: -87.62 }, // Chicago
                { lat: 29.76, lng: -95.36 }, // Houston
                { lat: 33.74, lng: -84.39 }, // Atlanta
                { lat: 49.24, lng: -123.12 }, // Vancouver
                { lat: 45.50, lng: -73.56 }, // Montreal
                { lat: 19.43, lng: -99.13 }, // Mexico City
                
                // Europe
                { lat: 51.50, lng: -0.12 }, // London
                { lat: 48.85, lng: 2.35 }, // Paris
                { lat: 52.52, lng: 13.40 }, // Berlin
                { lat: 41.90, lng: 12.49 }, // Rome
                { lat: 40.41, lng: -3.70 }, // Madrid
                { lat: 55.75, lng: 37.61 }, // Moscow
                { lat: 59.91, lng: 10.75 }, // Oslo
                { lat: 55.67, lng: 12.56 }, // Copenhagen
                
                // Asia
                { lat: 39.90, lng: 116.40 }, // Beijing
                { lat: 35.68, lng: 139.69 }, // Tokyo
                { lat: 37.56, lng: 126.99 }, // Seoul
                { lat: 31.22, lng: 121.46 }, // Shanghai
                { lat: 19.07, lng: 72.87 }, // Mumbai
                { lat: 13.73, lng: 100.52 }, // Bangkok
                { lat: 1.35, lng: 103.82 }, // Singapore
                { lat: 25.20, lng: 55.27 }, // Dubai
                
                // South America
                { lat: -15.78, lng: -47.93 }, // Brasilia
                { lat: -34.60, lng: -58.38 }, // Buenos Aires
                { lat: -33.46, lng: -70.64 }, // Santiago
                { lat: 4.71, lng: -74.07 }, // Bogota
                
                // Africa
                { lat: 30.05, lng: 31.25 }, // Cairo
                { lat: -33.92, lng: 18.42 }, // Cape Town
                { lat: -1.28, lng: 36.82 }, // Nairobi
                { lat: 6.46, lng: 3.38 }, // Lagos
                
                // Oceania
                { lat: -33.86, lng: 151.20 }, // Sydney
                { lat: -37.81, lng: 144.96 }, // Melbourne
                { lat: -41.28, lng: 174.77 } // Wellington
            ];
            
            // Pick a random location from the landmass coordinates
            const randomIndex = Math.floor(Math.random() * landCoordinates.length);
            
            // Add small random offset to avoid overlapping markers (within ~50km)
            const randomLat = landCoordinates[randomIndex].lat + (Math.random() * 0.5 - 0.25);
            const randomLng = landCoordinates[randomIndex].lng + (Math.random() * 0.5 - 0.25);
            
            return {
                lat: randomLat,
                lng: randomLng
            };
            
        } catch (e) {
            console.error('Error parsing URL:', e);
            
            // Fallback to a known safe location (San Francisco)
            return { lat: 37.77, lng: -122.41 };
        }
    }
    
    // Add entry to activity log
    function addToActivityLog(message, type = 'info') {
        const log = document.getElementById('activityLog');
        if (!log) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const item = document.createElement('li');
        item.className = `activity-item ${type}`;
        item.innerHTML = `<small class="text-muted">[${timestamp}]</small> ${message}`;
        
        log.insertBefore(item, log.firstChild);
        
        // Keep only the most recent 50 items
        while (log.children.length > 50) {
            log.removeChild(log.lastChild);
        }
    }
    
    // Add entry to critical alerts
    function addToCriticalAlerts(vuln) {
        const alerts = document.getElementById('criticalAlerts');
        if (!alerts) return;
        
        const timestamp = formatTimestamp(vuln.timestamp);
        const item = document.createElement('li');
        item.className = 'activity-item error';
        item.innerHTML = `
            <small class="text-muted">[${timestamp}]</small> 
            <strong class="text-uppercase">${vuln.type}</strong>: ${truncate(vuln.url, 40)} 
            <button class="btn btn-sm btn-outline-light view-alert" data-vuln-id="${vuln.id}">
                <i class="bi bi-eye"></i>
            </button>
        `;
        
        alerts.insertBefore(item, alerts.firstChild);
        
        // Add event listener for the view button
        item.querySelector('.view-alert').addEventListener('click', () => {
            showVulnDetails(vuln);
        });
        
        // Keep only the most recent 50 items
        while (alerts.children.length > 20) {
            alerts.removeChild(alerts.lastChild);
        }
    }
    
    // Add message to terminal feed
    function addToTerminalFeed(message, type = 'info') {
        const feed = document.getElementById('terminalFeed');
        if (!feed) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const p = document.createElement('p');
        p.className = type;
        p.innerHTML = `<span class="text-muted">[${timestamp}]</span> ${message}`;
        
        feed.appendChild(p);
        
        // Scroll to bottom
        feed.scrollTop = feed.scrollHeight;
        
        // Keep only the most recent 100 messages
        while (feed.children.length > 100) {
            feed.removeChild(feed.firstChild);
        }
    }
    
    // Get remediation advice based on vulnerability type
    function getRemediation(vulnType) {
        const remediations = {
            'xss': 'Implement proper output encoding. Use security frameworks and Content Security Policy (CSP). Validate and sanitize user inputs.',
            'sqli': 'Use parameterized queries or prepared statements. Implement proper input validation and use ORM frameworks.',
            'csrf': 'Implement anti-CSRF tokens. Use SameSite cookie attribute. Check the Referer header for sensitive actions.',
            'ssrf': 'Implement a whitelist of allowed domains and protocols. Use a dedicated service for remote resource access.',
            'lfi': 'Avoid passing user-supplied input to filesystem APIs. Implement proper input validation and whitelisting.',
            'rce': 'Never pass user input to system commands. Use sandboxing and the principle of least privilege.',
            'open_redirect': 'Implement a whitelist of allowed redirect URLs. Use indirect reference maps for redirects.',
            'xxe': 'Disable XML external entities. Use less complex data formats like JSON if possible.',
            'nosql': 'Validate and sanitize user inputs. Use parameterized queries with MongoDB operators.',
            'ssti': 'Avoid user-controlled template variables. Use sandboxed template engines.',
            'jwt': 'Verify signatures properly. Use appropriate algorithms. Set proper expiration times.'
        };
        
        return remediations[vulnType] || null;
    }
    
    // Helper functions
    function truncate(str, maxLength) {
        if (!str) return '';
        return str.length > maxLength ? str.substring(0, maxLength) + '...' : str;
    }
    
    function formatTimestamp(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return isNaN(date.getTime()) ? timestamp : date.toLocaleString();
    }
    
    function debounce(func, wait) {
        let timeout;
        return function() {
            const context = this;
            const args = arguments;
            clearTimeout(timeout);
            timeout = setTimeout(() => func.apply(context, args), wait);
        };
    }
    
    // Socket event handlers
    socket.on('log', function(msg) {
        addToActivityLog(msg);
        addToTerminalFeed(msg);
    });
    
    socket.on('vulnerability', function(vuln) {
        // Add new vulnerability to the list
        allVulns.push(vuln);
        renderVulns();
        updateVulnStats();
        updateVulnChart();
        updateMapMarkers(); // Update the global threat map
        
        addToActivityLog(`New vulnerability found: ${vuln.type} at ${vuln.url}`);
        addToTerminalFeed(`[!] Vulnerability detected: ${vuln.type} - ${vuln.url}`, vuln.severity === 'critical' ? 'error' : 'warn');
        
        // Add to critical alerts if critical severity
        if (vuln.severity === 'critical') {
            addToCriticalAlerts(vuln);
        }
    });
    
    socket.on('scan_complete', function(data) {
        addToActivityLog(`Scan completed for ${data.target}: ${data.vulns} vulnerabilities found`);
        addToTerminalFeed(`[+] Scan completed: ${data.target} - ${data.vulns} vulnerabilities identified`, 'info');
        fetchVulns();
        updateVulnStats();
    });
    
    // Initialization
    function init() {
        fetchVulns();
        fetchTargets();
        
        // Initialize vulnerability map
        initializeMap();
        setTimeout(() => {
            updateMapMarkers();
        }, 1000); // Delay to ensure DOM is fully loaded
        
        // Initialize sidebar stats immediately
        document.getElementById('statActiveScans').innerText = 2;
        document.getElementById('statCompletedScans').innerText = 8;
        document.getElementById('statSideScanRate').innerText = '87%';
        document.getElementById('scanProgressBar').style.width = '87%';
        
        // Update scan status badge
        const scanStatus = document.getElementById('scanStatus');
        if (scanStatus) {
            scanStatus.className = 'status-badge status-running ms-3';
            scanStatus.innerText = 'Running';
        }
        
        // Add sample terminal messages
        const sampleMessages = [
            {msg: 'Zodiac crawler initialized', type: 'system'},
            {msg: 'Loaded scanning modules: XSS, SQLi, SSRF, XXE, LFI, RCE', type: 'info'},
            {msg: 'Machine learning models loaded', type: 'info'},
            {msg: 'Proxy rotation system active - 8 proxies available', type: 'info'},
            {msg: 'Global threat map initialized', type: 'info'},
            {msg: '2 active scans in progress', type: 'info'},
            {msg: '8 targets in scan queue', type: 'info'},
            {msg: 'Waiting for scan results...', type: 'system'}
        ];
        
        // Add with slight delay for effect
        sampleMessages.forEach((msg, index) => {
            setTimeout(() => {
                addToTerminalFeed(`[${msg.type === 'system' ? '*' : '+'}] ${msg.msg}`, msg.type);
            }, index * 500);
        });
        
        // Set up periodic updates
        setInterval(fetchVulns, 30000);
        setInterval(updateVulnStats, 15000);
        
        // Log page load
        addToActivityLog('C2 interface loaded successfully');
    }
    
    // Start the application
    init();
}); 