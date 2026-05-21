/* VulnScan Dashboard v2.0 */
'use strict';

// ── State ──────────────────────────────────────────────────────────────────────
let allVulns       = [];
let activeFilter   = 'all';
let severityChart  = null;
let typesChart     = null;
let scanRunning    = false;

// ── Socket.IO ──────────────────────────────────────────────────────────────────
const socket = io({ transports: ['websocket', 'polling'] });

socket.on('connect',    () => log('[*] Connected to server', 'info'));
socket.on('disconnect', () => log('[!] Disconnected',        'warn'));
socket.on('log',        msg => log(msg));
socket.on('vuln_found', v  => { allVulns.push(v); renderVulnTable(); updateStats(); updateCharts(); });
socket.on('scan_done',  ()  => { scanDone(); refreshVulns(); });

// ── Navigation ─────────────────────────────────────────────────────────────────
function nav(el) {
  const page = el.dataset.page;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  el.classList.add('active');
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  document.getElementById('page-title').textContent =
    el.textContent.trim().replace(/\d+$/, '').trim();

  if (page === 'vulns')    { refreshVulns(); }
  if (page === 'targets')  { refreshTargets(); }
  if (page === 'reports')  { refreshReports(); }
  if (page === 'dashboard'){ refreshVulns(); }
}

// ── Logging ────────────────────────────────────────────────────────────────────
function log(msg, type = 'info') {
  const cls = { info: 'log-info', warn: 'log-warn', found: 'log-found', error: 'log-error' }[type] || 'log-info';
  const line = `<div class="log-line ${cls}">${escHtml(msg)}</div>`;
  ['log-feed', 'log-feed-scan'].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.insertAdjacentHTML('beforeend', line); el.scrollTop = el.scrollHeight; }
  });
}

function clearLog() {
  ['log-feed', 'log-feed-scan'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '<span class="log-info">[*] Log cleared.</span>';
  });
}

// ── Scan ───────────────────────────────────────────────────────────────────────
async function startScan() {
  const target = document.getElementById('scan-target').value.trim();
  if (!target) { toast('Please enter a target URL.', 'warn'); return; }
  if (scanRunning) { toast('Scan already running.', 'warn'); return; }

  scanRunning = true;
  const btn = document.getElementById('btn-run');
  btn.disabled = true;
  btn.textContent = '⏳ Scanning…';

  // Show progress
  document.getElementById('scan-progress-wrap').style.display = 'block';
  animateProgress();

  log(`[*] Starting scan on ${target}`, 'info');

  const payload = {
    url:        target,
    modules:    document.getElementById('scan-modules').value,
    depth:      parseInt(document.getElementById('scan-depth').value) || 3,
    max_urls:   parseInt(document.getElementById('scan-maxurls').value) || 50,
    threads:    parseInt(document.getElementById('scan-threads').value) || 5,
    proxy:      document.getElementById('scan-proxy').value.trim() || null,
    ml:         document.getElementById('opt-ml').checked,
    telegram:   document.getElementById('opt-telegram').checked,
    notify_each:document.getElementById('opt-notify-each').checked,
    verbose:    document.getElementById('opt-verbose').checked,
    format:     document.getElementById('scan-format').value,
  };

  try {
    const res = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    toast('Scan started!');
  } catch (e) {
    log(`[!] Scan start failed: ${e.message}`, 'error');
    toast('Failed to start scan.', 'error');
    scanDone();
  }
}

function scanDone() {
  scanRunning = false;
  const btn = document.getElementById('btn-run');
  if (btn) { btn.disabled = false; btn.textContent = '▶ Run Scan'; }
  const wrap = document.getElementById('scan-progress-wrap');
  if (wrap) wrap.style.display = 'none';
  log('[+] Scan complete.', 'found');
  toast('Scan complete!');
  updateNavBadge();
}

function resetForm() {
  document.getElementById('scan-target').value  = '';
  document.getElementById('scan-proxy').value   = '';
  document.getElementById('scan-depth').value   = '3';
  document.getElementById('scan-maxurls').value = '50';
  document.getElementById('scan-threads').value = '5';
  document.getElementById('scan-modules').value = 'all';
  document.getElementById('scan-format').value  = 'html';
  ['opt-ml','opt-telegram','opt-notify-each','opt-verbose'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.checked = id === 'opt-ml';
  });
}

let _progInterval = null;
function animateProgress() {
  let v = 0;
  const bar = document.getElementById('scan-progress-bar');
  const label = document.getElementById('scan-progress-label');
  const phases = ['Crawling…', 'Scanning…', 'ML analysis…', 'Generating report…'];
  let pi = 0;
  clearInterval(_progInterval);
  _progInterval = setInterval(() => {
    if (!scanRunning) { bar.style.width = '100%'; clearInterval(_progInterval); return; }
    v = Math.min(v + Math.random() * 2, 92);
    bar.style.width = v + '%';
    if (v > (pi + 1) * 23 && pi < phases.length - 1) pi++;
    label.textContent = phases[pi];
  }, 400);
}

// ── Data fetching ──────────────────────────────────────────────────────────────
async function refreshVulns() {
  try {
    const res = await fetch('/api/vulns?include_all=true');
    const data = await res.json();
    allVulns = Array.isArray(data) ? data : [];
    renderVulnTable();
    renderRecentTable();
    updateStats();
    updateCharts();
    updateNavBadge();
  } catch (e) {
    console.error('refreshVulns:', e);
  }
}

async function refreshTargets() {
  try {
    const res  = await fetch('/api/targets');
    const data = await res.json();
    const tbody = document.getElementById('targets-table-body');
    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:40px;color:var(--text-muted)">No targets scanned yet</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(t => {
      const cnt = allVulns.filter(v => (v.url||'').startsWith(t)).length;
      return `<tr>
        <td class="mono url-cell">${escHtml(t)}</td>
        <td><span class="badge ${cnt ? 'badge-high' : ''}">${cnt}</span></td>
        <td style="color:var(--text-muted)">—</td>
        <td>
          <button class="btn btn-ghost" style="padding:4px 10px;font-size:11px" onclick="rescan('${escHtml(t)}')">Rescan</button>
        </td>
      </tr>`;
    }).join('');
  } catch (e) { console.error(e); }
}

async function refreshReports() {
  try {
    const res  = await fetch('/reports/list');
    const data = await res.json();
    const tbody = document.getElementById('reports-table-body');
    if (!Array.isArray(data) || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:40px;color:var(--text-muted)">No reports yet</td></tr>';
      return;
    }
    tbody.innerHTML = data.map(r => `<tr>
      <td class="mono">${escHtml(r.name)}</td>
      <td><span class="badge badge-medium">${escHtml(r.format||'html')}</span></td>
      <td style="color:var(--text-muted)">${escHtml(r.size)}</td>
      <td style="color:var(--text-muted)">${escHtml(r.date)}</td>
      <td><a href="/reports/download/${encodeURIComponent(r.name)}" class="btn btn-ghost" style="padding:4px 10px;font-size:11px">↓ Download</a></td>
    </tr>`).join('');
  } catch(e) { console.error(e); }
}

// ── Render ─────────────────────────────────────────────────────────────────────
function renderVulnTable() {
  const tbody = document.getElementById('vuln-table-body');
  const data  = activeFilter === 'all'
    ? allVulns
    : allVulns.filter(v => (v.severity||'medium').toLowerCase() === activeFilter);

  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;padding:40px;color:var(--text-muted)">No vulnerabilities found</td></tr>';
    return;
  }
  tbody.innerHTML = data.map((v, i) => {
    const sev    = (v.severity || sevOf(v.type || '')).toLowerCase();
    const ts     = v.timestamp || '';
    return `<tr>
      <td style="color:var(--text-muted)">${i+1}</td>
      <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
      <td><strong>${escHtml(v.type||'?').toUpperCase()}</strong></td>
      <td class="mono">${escHtml(v.parameter||'N/A')}</td>
      <td class="mono" style="color:var(--medium);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(String(v.payload||''))}">${escHtml(String(v.payload||'N/A').slice(0,60))}</td>
      <td class="mono url-cell" title="${escHtml(v.url||'')}">${escHtml(v.url||'N/A')}</td>
      <td style="color:var(--text-muted);white-space:nowrap;font-size:11px">${ts.slice(0,16)}</td>
    </tr>`;
  }).join('');
}

function renderRecentTable() {
  const tbody  = document.getElementById('recent-table');
  if (!tbody) return;
  const recent = allVulns.slice(-10).reverse();
  if (!recent.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;padding:32px;color:var(--text-muted)">No data — run a scan first</td></tr>';
    return;
  }
  tbody.innerHTML = recent.map(v => {
    const sev = (v.severity || sevOf(v.type || '')).toLowerCase();
    return `<tr>
      <td><span class="badge badge-${sev}">${sev.toUpperCase()}</span></td>
      <td><strong>${escHtml(v.type||'?').toUpperCase()}</strong></td>
      <td class="mono">${escHtml(v.parameter||'N/A')}</td>
      <td class="mono url-cell" title="${escHtml(v.url||'')}">${escHtml(v.url||'N/A')}</td>
      <td style="color:var(--text-muted);font-size:11px">${(v.timestamp||'').slice(0,16)}</td>
    </tr>`;
  }).join('');
}

// ── Stats ──────────────────────────────────────────────────────────────────────
function updateStats() {
  const c = countBySev(allVulns);
  setText('stat-total',    allVulns.length);
  setText('stat-critical', c.critical || 0);
  setText('stat-high',     c.high     || 0);
  setText('stat-medium',   c.medium   || 0);
  const hosts = new Set(allVulns.map(v => { try { return new URL(v.url||'').hostname; } catch { return ''; } }));
  setText('stat-targets', hosts.size);
}

function updateNavBadge() {
  const el = document.getElementById('nav-vuln-count');
  if (el) el.textContent = allVulns.length;
}

function countBySev(list) {
  const c = {};
  list.forEach(v => { const s = (v.severity || sevOf(v.type||'')).toLowerCase(); c[s] = (c[s]||0)+1; });
  return c;
}

function countByType(list) {
  const c = {};
  list.forEach(v => { const t = (v.type||'unknown').toLowerCase(); c[t] = (c[t]||0)+1; });
  return c;
}

// ── Charts ─────────────────────────────────────────────────────────────────────
function updateCharts() {
  updateSeverityChart();
  updateTypesChart();
}

function updateSeverityChart() {
  const c   = countBySev(allVulns);
  const labels = ['Critical', 'High', 'Medium', 'Low'];
  const vals   = [c.critical||0, c.high||0, c.medium||0, c.low||0];
  const colors = ['#ff4d4d','#f0883e','#d29922','#3fb950'];
  const ctx    = document.getElementById('chart-severity').getContext('2d');
  if (severityChart) severityChart.destroy();
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: vals, backgroundColor: colors, borderWidth: 0 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#7d8590', font: { size: 11 } } },
      },
    },
  });
}

function updateTypesChart() {
  const c      = countByType(allVulns);
  const labels = Object.keys(c);
  const vals   = Object.values(c);
  const ctx    = document.getElementById('chart-types').getContext('2d');
  if (typesChart) typesChart.destroy();
  typesChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data: vals,
        backgroundColor: 'rgba(88,166,255,.4)',
        borderColor:     '#58a6ff',
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#7d8590' }, grid: { color: '#21262d' } },
        y: { ticks: { color: '#7d8590', stepSize: 1 }, grid: { color: '#21262d' }, beginAtZero: true },
      },
    },
  });
}

// ── Filters ────────────────────────────────────────────────────────────────────
function filterVulns(sev, btn) {
  activeFilter = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderVulnTable();
}

// ── Actions ────────────────────────────────────────────────────────────────────
async function rescan(target) {
  try {
    await fetch('/api/targets/rescan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target }),
    });
    toast(`Rescanning ${target}…`);
  } catch(e) { toast('Rescan failed.', 'error'); }
}

async function saveSettings() {
  const s = {
    telegram_token:  document.getElementById('s-tg-token').value.trim(),
    telegram_chat_id:document.getElementById('s-tg-chatid').value.trim(),
    send_telegram:   document.getElementById('s-tg-report').checked,
    ml:              document.getElementById('s-ml').checked,
    depth:           parseInt(document.getElementById('s-depth').value)||3,
    max_urls:        parseInt(document.getElementById('s-maxurls').value)||50,
  };
  try {
    await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(s),
    });
    toast('Settings saved!');
  } catch(e) { toast('Save failed.', 'error'); }
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}
function sevOf(type) {
  const m = { sqli:'critical', rce:'critical', file_inclusion:'critical', lfi:'critical',
              xss:'high', ssrf:'high', subdomain_takeover:'high',
              csrf:'medium', open_redirect:'medium', cors:'medium', ssl_tls:'medium' };
  return m[type] || 'medium';
}

let _toastTimer = null;
function toast(msg, type = 'info') {
  const el = document.getElementById('toast');
  if (!el) return;
  el.textContent = msg;
  el.style.borderColor = type === 'error' ? 'var(--red)' : type === 'warn' ? 'var(--yellow)' : 'var(--accent)';
  el.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  refreshVulns();

  // Status polling
  setInterval(async () => {
    try {
      const r = await fetch('/api/scan/status');
      const d = await r.json();
      const dot  = document.getElementById('status-dot');
      const text = document.getElementById('status-text');
      if (d.status === 'running') {
        dot.classList.add('running');
        text.textContent = 'Scanning…';
      } else {
        dot.classList.remove('running');
        text.textContent = 'Idle';
      }
    } catch(_) {}
  }, 5000);
});
