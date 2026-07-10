let engineUrl = '';

// ── Loading screen controller ─────────────────────────────────────────────────
const _loader = {
    steps: [
        { pct: 15, label: 'Initializing engine\u2026' },
        { pct: 35, label: 'Loading threat intelligence\u2026' },
        { pct: 55, label: 'Starting real-time protection\u2026' },
        { pct: 75, label: 'Connecting to security services\u2026' },
        { pct: 90, label: 'Loading interface\u2026' },
        { pct: 100, label: 'Ready' },
    ],
    _cur: 0,
    set(pct, label) {
        const bar = document.getElementById('loader-bar');
        const status = document.getElementById('loader-status');
        if (bar) bar.style.width = pct + '%';
        if (status) {
            status.textContent = label;
            if (pct === 100) status.classList.add('ready');
        }
        // activate dots 0-3 as pct crosses 25/50/75/100
        [0,1,2,3].forEach(i => {
            const dot = document.getElementById('ldot-' + i);
            if (!dot) return;
            const threshold = (i + 1) * 25;
            if (pct >= 100) { dot.className = 'loader-dot done'; }
            else if (pct >= threshold) { dot.className = 'loader-dot done'; }
            else if (pct >= threshold - 24) { dot.className = 'loader-dot active'; }
            else { dot.className = 'loader-dot'; }
        });
    },
    step(n) {
        const s = this.steps[Math.min(n, this.steps.length - 1)];
        this.set(s.pct, s.label);
    },
    hide() {
        this.set(100, 'Ready');
        setTimeout(() => {
            const el = document.getElementById('sentinel-loader');
            if (el) el.classList.add('fade-out');
        }, 600);
    },
    init() {
        // Show version
        try {
            const ver = document.getElementById('loader-version');
            if (ver) ver.textContent = 'v1.0.2 beta';
        } catch(e) {}
        this.set(5, 'Starting up\u2026');
    },
};
_loader.init();

// ── Non-blocking notification helpers ────────────────────────────────────────
function _toast(msg, ok = true, duration = 3500) {
    const el = document.createElement('div');
    el.style.cssText = `position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:99999;padding:10px 18px;border-radius:10px;font-size:13px;font-weight:600;color:#fff;background:${ok ? 'rgba(16,185,129,.92)' : 'rgba(239,68,68,.92)'};box-shadow:0 8px 32px rgba(0,0,0,.5);pointer-events:none;white-space:nowrap;transition:opacity .3s`;
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, duration);
}

function _confirm(msg) {
    return new Promise(resolve => {
        const overlay = document.createElement('div');
        overlay.style.cssText = 'position:fixed;inset:0;background:rgba(7,7,10,.8);z-index:99997;display:flex;align-items:center;justify-content:center;backdrop-filter:blur(3px)';
        overlay.innerHTML = `<div style="background:#111117;border:1px solid #27272a;border-radius:14px;padding:28px 32px;max-width:380px;width:90%;text-align:center"><p style="font-size:14px;color:#e4e4e7;margin:0 0 20px;line-height:1.6">${msg}</p><div style="display:flex;gap:10px;justify-content:center"><button id="_c_cancel" style="flex:1;padding:8px 16px;border-radius:8px;background:#1c1c21;border:1px solid #27272a;color:#a1a1aa;font-size:13px;cursor:pointer">Cancel</button><button id="_c_ok" style="flex:1;padding:8px 16px;border-radius:8px;background:rgba(239,68,68,.15);border:1px solid rgba(239,68,68,.3);color:#f87171;font-size:13px;font-weight:600;cursor:pointer">Confirm</button></div></div>`;
        document.body.appendChild(overlay);
        overlay.querySelector('#_c_ok').onclick = () => { overlay.remove(); resolve(true); };
        overlay.querySelector('#_c_cancel').onclick = () => { overlay.remove(); resolve(false); };
    });
}

const _THREAT_EXPLANATIONS = {
    virustotal: { label: 'VirusTotal Match', what: 'Known malware identified by multiple antivirus engines', does: 'May steal data, damage files, or provide remote access to attackers' },
    malwarebazaar: { label: 'MalwareBazaar Match', what: 'File hash matches a known malware sample in MalwareBazaar database', does: 'Confirmed malicious — treat as active threat' },
    threatfox: { label: 'ThreatFox IOC', what: 'File is listed as an Indicator of Compromise in ThreatFox', does: 'Associated with active threat campaigns or C2 infrastructure' },
    yara: { label: 'YARA Rule Match', what: 'File content matches a malware pattern defined by YARA rules', does: 'Exhibits characteristics of known malware families' },
    virus: { label: 'Virus Detected', what: 'ClamAV antivirus engine flagged this file as malicious', does: 'Can infect other files, spread through the system, or exfiltrate data' },
    known_malware: { label: 'Known Malware Hash', what: 'SHA256 hash matches a confirmed malware sample', does: 'Confirmed malicious binary — do not execute' },
    high_entropy: { label: 'High Entropy Content', what: 'File contains near-random byte patterns consistent with encryption or packing', does: 'Packed or encrypted payloads are commonly used to hide malware from scanners' },
    embedded_executable: { label: 'Embedded Executable', what: 'A Windows (MZ/PE) or Linux (ELF) executable header was found inside a non-executable file', does: 'Attackers embed executables inside documents or images to bypass security filters' },
    suspicious_script: { label: 'Suspicious Script', what: 'Script file contains patterns associated with malicious activity', does: 'Can execute system commands, download payloads, or modify registry/startup items' },
    suspicious_content: { label: 'Suspicious Content', what: 'File contains code patterns linked to malware behaviour', does: 'May attempt to execute hidden commands or obfuscated payloads' },
    suspicious_extension: { label: 'Double Extension', what: 'File uses a double extension (e.g. document.pdf.exe) to disguise its true type', does: 'Trick users into running malware thinking it is a safe document' },
    suspicious_name: { label: 'Suspicious Name', what: 'Executable filename matches keywords associated with piracy tools or malware loaders', does: 'Crack/keygen/patch tools frequently bundle trojans or adware' },
};

const _SEVERITY_CARD_STYLE = {
    critical: 'border-color:rgba(239,68,68,0.4);background:rgba(239,68,68,0.05)',
    high:     'border-color:rgba(249,115,22,0.4);background:rgba(249,115,22,0.05)',
    medium:   'border-color:rgba(245,158,11,0.4);background:rgba(245,158,11,0.05)',
    low:      'border-color:rgba(59,130,246,0.4);background:rgba(59,130,246,0.05)',
    default:  'border-color:#27272a;background:#16161a',
};
const _SEVERITY_BADGE_STYLE = {
    critical: 'background:#ef4444;color:#fff',
    high:     'background:#f97316;color:#fff',
    medium:   'background:#f59e0b;color:#000',
    low:      'background:#3b82f6;color:#fff',
    default:  'background:#27272a;color:#a1a1aa',
};

async function initEngine() {
    _loader.step(0); // Initializing engine
    if (window.electronAPI) {
        engineUrl = await window.electronAPI.getEngineUrl();
    } else {
        engineUrl = 'http://127.0.0.1:18081';
    }
    console.log('Engine URL:', engineUrl);
    setFeedbackType('bug');
}

function showView(viewName) {
    document.querySelectorAll('.view').forEach(el => el.classList.add('hidden'));
    document.getElementById(`view-${viewName}`).classList.remove('hidden');

    document.querySelectorAll('.sidebar-item').forEach(el => el.classList.remove('active'));
    document.getElementById(`nav-${viewName}`).classList.add('active');

    const titles = {
        dashboard: 'Dashboard',
        network: 'Network Scan',
        threats: 'Threats',
        'network-threats': 'Network Threats',
        vulns: 'Vulnerabilities',
        scanner: 'File Scanner',
        quarantine: 'Quarantine',
        scans: 'Scans',
        license: 'License & Subscription',
        settings: 'Settings',
        feedback: 'Send Feedback',
    };
    document.getElementById('page-title').textContent = titles[viewName] || viewName;
    if (viewName === 'license') loadLicense();
    if (viewName === 'quarantine') loadQuarantine();
    if (viewName === 'scanner') { loadThreatResults(); loadIgnoreList(); }
    if (viewName === 'feedback') _updateFeedbackConnStatus();
}

async function _updateFeedbackConnStatus() {
    const el  = document.getElementById('feedback-conn-status');
    const dot = document.getElementById('feedback-conn-dot');
    if (!el) return;
    try {
        const cfg = await apiGet('/api/beta/config');
        if (cfg.configured && cfg.admin_url) {
            el.textContent = 'Connected to admin server';
            el.style.color = '#4ade80';
            if (dot) dot.style.background = '#22c55e';
        } else {
            el.textContent = 'Not configured — Settings → Beta Program';
            el.style.color = '#fbbf24';
            if (dot) dot.style.background = '#f59e0b';
        }
    } catch(e) {
        el.textContent = 'Engine offline';
        el.style.color = '#f87171';
        if (dot) dot.style.background = '#ef4444';
    }
    loadAdminMessages();
}

const _FEEDBACK_TYPE_META = {
    bug:        { color: 'rgba(239,68,68,0.07)', border: 'rgba(239,68,68,0.18)', textColor: '#fca5a5', label: 'Bug Report',    hint: 'Describe what went wrong, steps to reproduce, and any error messages you saw.' },
    suggestion: { color: 'rgba(59,130,246,0.07)', border: 'rgba(59,130,246,0.18)', textColor: '#93c5fd', label: 'Suggestion',   hint: 'Share a feature idea or improvement you would like to see.' },
    diagnostic: { color: 'rgba(139,92,246,0.07)', border: 'rgba(139,92,246,0.18)', textColor: '#c4b5fd', label: 'Diagnostics', hint: 'Send your system diagnostics to help us investigate issues on your machine.' },
};

function setFeedbackType(type) {
    document.getElementById('feedback-type').value = type;
    const meta = _FEEDBACK_TYPE_META[type] || _FEEDBACK_TYPE_META.bug;
    const hint = document.getElementById('feedback-type-hint');
    if (hint) {
        hint.style.background = meta.color;
        hint.style.borderColor = meta.border;
        hint.style.color = meta.textColor;
        hint.innerHTML = `<strong style="color:${meta.textColor}">${meta.label}</strong> — ${meta.hint}`;
    }
    ['bug','suggestion','diagnostic'].forEach(t => {
        const btn = document.getElementById('ftab-' + t);
        if (!btn) return;
        btn.style.background = t === type ? '#1c1c28' : 'transparent';
        btn.style.color      = t === type ? '#fff'    : '#71717a';
        btn.style.boxShadow  = t === type ? 'inset 0 0 0 1px rgba(255,255,255,0.08)' : 'none';
    });
}

async function loadAdminMessages() {
    const wrap = document.getElementById('admin-msg-list');
    if (!wrap) return;
    try {
        const cfg = await apiGet('/api/beta/config').catch(() => ({}));
        const adminUrl = cfg.admin_url || '';
        if (!adminUrl) { wrap.textContent = 'Connect to admin server to receive messages.'; return; }
        const msgs = await fetch(`${adminUrl}/api/messages`).then(r => r.json()).catch(() => []);
        const active = (msgs || []).filter(m => m.active);
        if (!active.length) { wrap.textContent = 'No messages from admin.'; return; }
        const _col = { info:'#60a5fa', warning:'#fbbf24', critical:'#f87171' };
        wrap.innerHTML = active.map(m => `
            <div style="padding:8px 10px;border-radius:8px;background:rgba(255,255,255,0.03);border:1px solid ${_col[m.level]||'#3b82f6'}33;margin-bottom:7px">
                ${m.title ? `<p style="font-size:12px;font-weight:700;color:#fff;margin-bottom:3px">${m.title}</p>` : ''}
                <p style="font-size:11px;color:#a1a1aa;line-height:1.5">${m.body}</p>
                <p style="font-size:10px;color:#52525b;margin-top:4px">${new Date(m.sent_at).toLocaleString()}</p>
            </div>`).join('');
    } catch(e) { wrap.textContent = 'Could not load messages.'; }
}

async function apiGet(path) {
    const res = await fetch(`${engineUrl}${path}`);
    return res.json();
}

async function apiPost(path, body = {}) {
    const res = await fetch(`${engineUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return res.json();
}

async function loadSystem() {
    try {
        const data = await apiGet('/api/system');
        document.getElementById('dash-cpu').textContent = data.cpu_percent.toFixed(1) + '%';
        document.getElementById('dash-cpu-bar').style.width = data.cpu_percent + '%';
        document.getElementById('dash-memory').textContent = data.memory.percent.toFixed(1) + '%';
        document.getElementById('dash-memory-bar').style.width = data.memory.percent + '%';
        document.getElementById('dash-disk').textContent = data.disk.percent.toFixed(1) + '%';
        document.getElementById('dash-disk-bar').style.width = data.disk.percent + '%';
    } catch (e) {
        console.error('System load failed', e);
    }
}

async function loadSubnet() {
    try {
        const data = await apiGet('/api/security/subnet');
        document.getElementById('scan-subnet').value = data.subnet || '10.0.0.0/24';
        document.getElementById('network-subnet').textContent = `Subnet: ${data.subnet || 'unknown'}`;
    } catch (e) {
        console.error('Subnet load failed', e);
    }
}

function renderDevices(devices) {
    const tbody = document.getElementById('devices-table');
    document.getElementById('device-count').textContent = `${devices.length} devices`;
    document.getElementById('dash-devices').textContent = devices.length;
    tbody.innerHTML = devices.map(d => `
        <tr class="border-b border-slate-700/30 hover:bg-slate-800/40 transition">
            <td class="py-3 font-medium text-white">${d.ip}</td>
            <td class="py-3">${d.hostname || d.ip}</td>
            <td class="py-3">${d.vendor || 'Unknown'}</td>
            <td class="py-3">${d.open_ports.join(', ') || 'None'}</td>
            <td class="py-3 text-slate-400">${new Date(d.first_seen).toLocaleString()}</td>
        </tr>
    `).join('');
    document.getElementById('dash-last-scan').textContent = new Date().toLocaleTimeString();
}

async function loadDevices() {
    try {
        const data = await apiGet('/api/security/devices');
        renderDevices(data.devices || []);
    } catch (e) {
        console.error('Devices load failed', e);
    }
}

async function runScan() {
    const btn = document.getElementById('scan-btn');
    const status = document.getElementById('scan-status');
    const subnet = document.getElementById('scan-subnet').value;
    const fullScan = document.getElementById('full-scan').checked;

    btn.disabled = true;
    btn.innerHTML = `<i data-lucide="loader" class="w-4 h-4 animate-spin"></i> Scanning...`;
    lucide.createIcons();
    status.classList.remove('hidden');
    status.innerHTML = `<div class="p-4 bg-slate-800/50 rounded-lg text-sm text-slate-300">Scanning ${subnet}... This may take a minute.</div>`;

    try {
        const data = await apiPost('/api/security/scan', { subnet, full_scan: fullScan });
        if (data.success) {
            status.innerHTML = `<div class="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">Scan complete. Found ${data.count} devices.</div>`;
            renderDevices(data.devices);
            addScanHistory(`Network scan found ${data.count} devices`, subnet);
        } else {
            status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Scan failed: ${data.error}</div>`;
        }
    } catch (e) {
        status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Request error: ${e}</div>`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="play" class="w-4 h-4"></i> Start Scan`;
        lucide.createIcons();
    }
}

function addScanHistory(message, target) {
    const container = document.getElementById('scan-history');
    if (container.querySelector('p.text-slate-500')) {
        container.innerHTML = '';
    }
    const div = document.createElement('div');
    div.className = 'p-4 bg-slate-800/50 rounded-xl flex items-center justify-between';
    div.innerHTML = `
        <div>
            <p class="text-sm font-medium text-white">${message}</p>
            <p class="text-xs text-slate-400">Target: ${target} · ${new Date().toLocaleString()}</p>
        </div>
        <span class="text-xs text-emerald-400 bg-emerald-500/10 px-2 py-1 rounded">Completed</span>
    `;
    container.prepend(div);
}

async function saveBaseline() {
    const btn = document.getElementById('baseline-btn');
    btn.disabled = true;
    btn.textContent = 'Saving...';
    try {
        const data = await apiPost('/api/security/baseline');
        if (data.success) {
            const count = data.baseline.devices.length;
            _toast(`Baseline saved with ${count} known devices.`);
        } else {
            _toast('Failed to save baseline.', false);
        }
    } catch (e) {
        _toast('Error saving baseline: ' + e, false);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i data-lucide="save" class="w-4 h-4"></i> Save Baseline`;
        lucide.createIcons();
    }
}

const _ALERT_SOURCE_LABEL = { scanner: 'File Threat', quarantine: 'Quarantined', network: 'Network', update: '⬇ App Update' };

let _cachedAlerts = [];
let _dropdownCloseTimer = null;

// Show score immediately as 100 on page load — updates when engine responds
(function() {
    const el = document.getElementById('security-score');
    const ring = el ? el.closest('.score-ring') : null;
    if (el) el.textContent = '100';
    if (ring) {
        ring.style.setProperty('--ring-color', '#22c55e');
        ring.style.setProperty('--ring-deg', '360deg');
    }
})();

function openAlertDropdown() {
    if (_dropdownCloseTimer) { clearTimeout(_dropdownCloseTimer); _dropdownCloseTimer = null; }
    const dd = document.getElementById('alert-dropdown');
    if (!dd) return;
    dd.style.display = 'block';
    _renderAlertDropdown();
}

function closeAlertDropdown() {
    _dropdownCloseTimer = setTimeout(() => {
        const dd = document.getElementById('alert-dropdown');
        if (dd) dd.style.display = 'none';
    }, 200);
}

function _renderAlertDropdown() {
    const list = document.getElementById('alert-dropdown-list');
    if (!list) return;
    if (_cachedAlerts.length === 0) {
        list.innerHTML = '<p style="font-size:12px;color:#71717a;padding:8px 4px">No alerts yet.</p>';
        return;
    }
    const _sevColor = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#3b82f6', default: '#52525b' };
    const _sevBg   = { critical: 'rgba(239,68,68,0.08)', high: 'rgba(249,115,22,0.08)', medium: 'rgba(245,158,11,0.08)', low: 'rgba(59,130,246,0.08)', default: 'rgba(39,39,42,0.5)' };
    const _sevBorder = { critical: 'rgba(239,68,68,0.35)', high: 'rgba(249,115,22,0.35)', medium: 'rgba(245,158,11,0.35)', low: 'rgba(59,130,246,0.35)', default: '#27272a' };
    const shown = _cachedAlerts.slice(0, 8);
    list.innerHTML = shown.map(a => {
        const sev = a.severity || 'default';
        const col = _sevColor[sev] || _sevColor.default;
        const bg  = _sevBg[sev]  || _sevBg.default;
        const bdr = _sevBorder[sev] || _sevBorder.default;
        const src = _ALERT_SOURCE_LABEL[a.source] || a.source;
        const ts  = a.timestamp ? new Date(a.timestamp).toLocaleString() : '';
        return `<div style="margin-bottom:6px;padding:10px 12px;border-radius:8px;background:${bg};border:1px solid ${bdr}">
            <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px">
                <span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:9999px;background:${col};color:${sev==='medium'?'#000':'#fff'};text-transform:uppercase;letter-spacing:.05em">${sev}</span>
                <span style="font-size:10px;padding:1px 6px;border-radius:4px;background:#1c1c21;border:1px solid #27272a;color:#a1a1aa">${src}</span>
                <span style="font-size:12px;font-weight:600;color:#fff;flex:1;min-width:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${a.label}</span>
                ${a.auto_quarantined ? '<span style="font-size:10px;padding:1px 6px;border-radius:4px;background:rgba(16,185,129,0.15);color:#34d399">Quarantined</span>' : ''}
            </div>
            <div style="font-size:11px;color:#a1a1aa;margin-bottom:3px"><span style="color:#71717a">Why: </span>${a.message}</div>
            <div style="font-size:11px;color:#a1a1aa;margin-bottom:3px"><span style="color:#71717a">Risk: </span>${a.risk}</div>
            ${a.path ? `<div style="font-size:10px;color:#52525b;font-family:monospace;word-break:break-all;margin-top:2px">${a.path}</div>` : ''}
            <div style="font-size:10px;color:#3f3f46;margin-top:4px">${ts}</div>
            ${a.source === 'update' && a.label && a.label.includes('ready') ? `<button onclick="installUpdateNow()" style="margin-top:8px;width:100%;padding:7px 12px;border-radius:8px;background:#3b82f6;border:none;color:#fff;font-size:12px;font-weight:700;cursor:pointer;letter-spacing:.01em">⬇ Install & Restart Now</button>` : ''}
        </div>`;
    }).join('');
    if (_cachedAlerts.length > 8) {
        list.innerHTML += `<button onclick="showView('threats')" style="width:100%;padding:8px;font-size:11px;color:#3b82f6;background:none;border:1px solid #27272a;border-radius:8px;cursor:pointer;margin-top:2px">View all ${_cachedAlerts.length} alerts →</button>`;
    }
}

async function loadAlerts() {
    try {
        const alerts = await apiGet('/api/alerts');
        _cachedAlerts = alerts;
        const list = document.getElementById('alerts-list');
        const unread = alerts.filter(a => !a.read).length;
        const total = alerts.length;

        document.getElementById('dash-threats').textContent = total;

        const badge = document.getElementById('threat-badge');
        if (unread > 0) {
            badge.textContent = unread;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }

        // Update bell badge in top bar
        const bellBadge = document.getElementById('bell-badge');
        if (bellBadge) {
            bellBadge.textContent = unread;
            bellBadge.style.display = unread > 0 ? 'flex' : 'none';
        }

        if (!list) return;
        if (alerts.length === 0) {
            list.innerHTML = '<p class="text-sm text-[#71717a]">No alerts. Run a scan to detect threats.</p>';
            return;
        }

        list.innerHTML = alerts.map(a => {
            const sev = a.severity || 'low';
            const cardSty = _SEVERITY_CARD_STYLE[sev] || _SEVERITY_CARD_STYLE.default;
            const badgeSty = _SEVERITY_BADGE_STYLE[sev] || _SEVERITY_BADGE_STYLE.default;
            const sourceLabel = _ALERT_SOURCE_LABEL[a.source] || a.source;
            const size = a.file_size ? formatFileSize(a.file_size) : null;
            return `
            <div class="rounded-xl border p-4 space-y-2" style="${cardSty}">
                <div class="flex items-start justify-between gap-2 flex-wrap">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-xs font-bold px-2 py-0.5 rounded-full uppercase tracking-wide" style="${badgeSty}">${sev}</span>
                        <span class="text-xs px-2 py-0.5 rounded bg-[#1c1c21] text-[#a1a1aa] border border-[#27272a]">${sourceLabel}</span>
                        <span class="text-sm font-semibold text-white">${a.label}</span>
                        ${a.auto_quarantined ? '<span class="text-xs px-2 py-0.5 rounded" style="background:rgba(16,185,129,0.15);color:#34d399">Auto-Quarantined</span>' : ''}
                    </div>
                    <span class="text-xs text-[#71717a] shrink-0">${new Date(a.timestamp).toLocaleString()}</span>
                </div>
                <div class="space-y-1 text-sm">
                    <div class="flex gap-2"><span class="text-[#71717a] w-14 shrink-0">Why:</span><span class="text-[#a1a1aa]">${a.message}</span></div>
                    <div class="flex gap-2"><span class="text-[#71717a] w-14 shrink-0">Risk:</span><span class="text-[#a1a1aa]">${a.risk}</span></div>
                    ${a.path ? `<div class="flex gap-2"><span class="text-[#71717a] w-14 shrink-0">File:</span><span class="text-xs text-[#71717a] font-mono break-all">${a.path}</span></div>` : ''}
                    ${size ? `<div class="flex gap-2"><span class="text-[#71717a] w-14 shrink-0">Size:</span><span class="text-[#a1a1aa] text-xs">${size}</span></div>` : ''}
                    ${a.file_hash ? `<div class="flex gap-2"><span class="text-[#71717a] w-14 shrink-0">SHA256:</span><span class="text-xs text-[#71717a] font-mono break-all">${a.file_hash}</span></div>` : ''}
                </div>
            </div>`;
        }).join('');
    } catch (e) {
        console.error('Alerts load failed', e);
    }
}

async function markRead(id) {
    try {
        await apiPost(`/api/security/alerts/${id}/read`);
        loadAlerts();
    } catch (e) {
        console.error('Mark read failed', e);
    }
}

async function clearAllAlerts() {
    try {
        await apiPost('/api/security/alerts/clear');
        _cachedAlerts = [];
        loadAlerts();
        document.getElementById('alert-dropdown').style.display = 'none';
    } catch (e) {
        // If endpoint doesn't exist yet, just clear the UI
        _cachedAlerts = [];
        const list = document.getElementById('alerts-list');
        if (list) list.innerHTML = '<p class="text-sm text-[#71717a]">No alerts.</p>';
        const ddList = document.getElementById('alert-dropdown-list');
        if (ddList) ddList.innerHTML = '<p style="font-size:12px;color:#71717a;padding:8px 4px">No alerts yet.</p>';
        document.getElementById('threat-badge')?.classList.add('hidden');
        const bell = document.getElementById('bell-badge');
        if (bell) bell.style.display = 'none';
        document.getElementById('alert-dropdown').style.display = 'none';
        updateSecurityScore(true, 0, 0);
    }
}

function updateSecurityScore(realtimeActive, threatCount, quarantineCount) {
    let score = 100;
    if (!realtimeActive) score -= 20;
    if (threatCount > 0) score -= Math.min(threatCount * 5, 40);
    if (quarantineCount > 0) score -= Math.min(quarantineCount * 2, 20);
    score = Math.max(score, 0);

    const el = document.getElementById('security-score');
    const ring = el ? el.closest('.score-ring') : null;
    const color = score >= 80 ? '#22c55e' : score >= 50 ? '#f59e0b' : '#ef4444';
    const deg = Math.round((score / 100) * 360);

    if (el) {
        el.textContent = score;
        el.style.color = color;
    }
    if (ring) {
        ring.style.setProperty('--ring-color', color);
        ring.style.setProperty('--ring-deg', deg + 'deg');
    }
}

async function loadThreatStatus() {
    try {
        const data = await apiGet('/api/threats/status').catch(() => ({ realtime_active: true, quarantine_count: 0 }));
        const badge = document.getElementById('quarantine-badge');
        if (data.quarantine_count > 0) {
            badge.textContent = data.quarantine_count;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }

        const clamavEl = document.getElementById('clamav-status');
        if (clamavEl) {
            if (data.clamav_available) {
                clamavEl.textContent = 'Available';
                clamavEl.className = 'text-xs text-emerald-400';
            } else {
                clamavEl.textContent = 'Not installed';
                clamavEl.className = 'text-xs text-amber-400';
            }
        }

        const toggle = document.getElementById('realtime-toggle');
        if (toggle) {
            toggle.textContent = data.realtime_active ? 'Stop Protection' : 'Start Protection';
            toggle.className = data.realtime_active
                ? 'px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-sm font-medium transition'
                : 'px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium transition';
        }
        updateSecurityScore(data.realtime_active, _cachedAlerts.length, data.quarantine_count || 0);

        // Update protection globe
        const wrap = document.getElementById('protection-globe-wrap');
        const lbl  = document.getElementById('protection-status-label');
        const sub  = document.getElementById('protection-status-sub');
        if (wrap) {
            if (data.realtime_active) {
                wrap.className = 'globe-wrap globe-active';
                if (lbl) { lbl.textContent = 'Protected'; lbl.style.color = '#22c55e'; }
                if (sub) { sub.textContent = 'Real-time monitoring on'; sub.style.color = '#22c55e'; }
            } else {
                wrap.className = 'globe-wrap globe-inactive';
                if (lbl) { lbl.textContent = 'Unprotected'; lbl.style.color = '#ef4444'; }
                if (sub) { sub.textContent = 'Real-time monitoring off'; sub.style.color = '#ef4444'; }
            }
        }
    } catch (e) {
        console.error('Threat status load failed', e);
    }
}

async function pickFile() {
    if (!window.electronAPI || !window.electronAPI.pickFile) {
        return _toast('File picker not available', false);
    }
    const selected = await window.electronAPI.pickFile();
    if (selected) {
        document.getElementById('scan-path').value = selected;
    }
}

async function pickDirectory() {
    if (!window.electronAPI || !window.electronAPI.pickDirectory) {
        return _toast('Directory picker not available', false);
    }
    const selected = await window.electronAPI.pickDirectory();
    if (selected) {
        document.getElementById('scan-path').value = selected;
    }
}

function getScanOptions() {
    const scanType = document.getElementById('scan-type')?.value || 'full';
    const recursive = document.getElementById('scan-recursive')?.checked ?? true;
    return { scan_type: scanType, recursive };
}

async function scanFile() {
    const input = document.getElementById('scan-path');
    const path = input.value.trim();
    if (!path) return _toast('Enter a file path or click Browse', false);
    await _runScan('/api/threats/scan/file', { path, ...getScanOptions() });
}

async function scanDirectory() {
    const input = document.getElementById('scan-path');
    const path = input.value.trim();
    if (!path) return _toast('Enter a directory path or click Browse', false);
    await _runScan('/api/threats/scan/directory', { path, ...getScanOptions() });
}

let _activeScanId = null;
let _progressPoller = null;

async function scanQuick(path) {
    const input = document.getElementById('scan-path');
    if (input) input.value = path;
    await _runScan('/api/threats/scan/directory', { path, ...getScanOptions() });
}

async function runFullScan(scanType = 'full') {
    const fullBtn = document.getElementById('full-scan-btn');
    const deepBtn = document.getElementById('deep-scan-btn');
    const quickBtn = document.getElementById('quick-scan-btn');
    [fullBtn, deepBtn, quickBtn].forEach(b => { if (b) b.disabled = true; });
    const isDeep = scanType === 'deep';
    const isQuick = scanType === 'quick';
    const labels = { quick: 'Quick Scan running\u2026', full: 'Full System Scan running\u2026', deep: 'Deep System Scan running\u2026' };
    try {
        const data = await apiPost('/api/threats/scan/full', { scan_type: scanType });
        if (!data.success) {
            const status = document.getElementById('scanner-status');
            status.classList.remove('hidden');
            status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Scan failed: ${data.error}</div>`;
            return;
        }
        _activeScanId = data.scan_id;
        const progressPanel = document.getElementById('scan-progress-panel');
        progressPanel.classList.remove('hidden');
        _resetProgressPanel(isDeep, isQuick);
        document.getElementById('scan-progress-label').textContent = labels[scanType] || 'Scanning\u2026';
        _startProgressPolling(_activeScanId);
    } catch (e) {
        _toast('Scan error: ' + e, false);
    } finally {
        [fullBtn, deepBtn, quickBtn].forEach(b => { if (b) b.disabled = false; });
    }
}

async function scanPreset(folderName) {
    try {
        const sys = await apiGet('/api/system');
        const home = sys.home_dir || (navigator.platform.includes('Win') ? `C:\\Users\\${sys.username || 'User'}` : `/Users/${sys.username || 'user'}`);
        const sep = home.includes('\\') ? '\\' : '/';
        const path = `${home}${sep}${folderName}`;
        await scanQuick(path);
    } catch (e) {
        _toast('Could not resolve home directory: ' + e, false);
    }
}

async function _runScan(endpoint, body) {
    const status = document.getElementById('scanner-status');
    const progressPanel = document.getElementById('scan-progress-panel');
    const fileBtn = document.getElementById('file-scan-btn');
    const dirBtn = document.getElementById('dir-scan-btn');
    const fullBtn = document.getElementById('full-scan-btn');
    const deepBtn = document.getElementById('deep-scan-btn');
    const quickScanBtn = document.getElementById('quick-scan-btn');
    const quickBtns = document.querySelectorAll('button[onclick^="scanQuick"], button[onclick^="scanPreset"]');

    fileBtn.disabled = true;
    dirBtn.disabled = true;
    if (fullBtn) fullBtn.disabled = true;
    if (deepBtn) deepBtn.disabled = true;
    if (quickScanBtn) quickScanBtn.disabled = true;
    quickBtns.forEach(b => b.disabled = true);
    status.classList.add('hidden');

    try {
        const data = await apiPost(endpoint, body);
        if (!data.success) {
            status.classList.remove('hidden');
            status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Scan failed: ${data.error}</div>`;
            return;
        }

        _activeScanId = data.scan_id;

        if (data.status === 'done' || endpoint.includes('/file')) {
            // Single-file scan completes synchronously
            _finishScan(data);
        } else {
            // Directory scan: show progress panel and start polling
            progressPanel.classList.remove('hidden');
            _resetProgressPanel();
            _startProgressPolling(_activeScanId);
        }
    } catch (e) {
        status.classList.remove('hidden');
        status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Request error: ${e}</div>`;
    } finally {
        fileBtn.disabled = false;
        dirBtn.disabled = false;
        if (fullBtn) fullBtn.disabled = false;
        if (deepBtn) deepBtn.disabled = false;
        if (quickScanBtn) quickScanBtn.disabled = false;
        quickBtns.forEach(b => b.disabled = false);
    }
}

function _resetProgressPanel(isDeep = false) {
    const color = isDeep ? 'purple' : 'blue';
    const bar = document.getElementById('scan-progress-bar');
    bar.style.width = '0%';
    bar.className = `h-2 rounded-full bg-${color}-500 transition-all duration-300`;
    document.getElementById('sp-files').textContent = '0';
    document.getElementById('sp-total').textContent = 'of 0';
    document.getElementById('sp-threats').textContent = '0';
    document.getElementById('sp-eta').textContent = '—';
    document.getElementById('sp-current-file').textContent = '—';
    document.getElementById('scan-progress-label').textContent = 'Scanning...';
    document.getElementById('scan-progress-spinner').className = `inline-block w-3 h-3 rounded-full bg-${color}-500 animate-pulse`;
    document.getElementById('scan-cancel-btn').classList.remove('hidden');
}

function _formatEta(seconds) {
    if (seconds <= 0 || !isFinite(seconds)) return '—';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function _startProgressPolling(scanId) {
    if (_progressPoller) clearInterval(_progressPoller);
    _startQuarantineAutoRefresh();
    _progressPoller = setInterval(async () => {
        try {
            const p = await apiGet(`/api/threats/scan/progress/${scanId}`);
            if (!p.success) {
                clearInterval(_progressPoller);
                _stopQuarantineAutoRefresh();
                return;
            }
            _updateProgressPanel(p);
            if (p.status === 'done' || p.status === 'cancelled' || p.status === 'error') {
                clearInterval(_progressPoller);
                _progressPoller = null;
                _stopQuarantineAutoRefresh();
                loadQuarantine();
                _finishScan(p);
            }
        } catch (e) {
            clearInterval(_progressPoller);
            _stopQuarantineAutoRefresh();
        }
    }, 500);
}

function _updateProgressPanel(p) {
    const pct = p.percent || 0;
    document.getElementById('scan-progress-bar').style.width = `${pct}%`;
    document.getElementById('sp-files').textContent = p.files_scanned || 0;
    document.getElementById('sp-total').textContent = `of ${p.total_files || 0}`;
    document.getElementById('sp-threats').textContent = p.threats_found || 0;
    document.getElementById('sp-eta').textContent = _formatEta(p.eta);
    const cur = p.current_file || '—';
    document.getElementById('sp-current-file').textContent = cur;
    document.getElementById('scan-progress-label').textContent =
        p.status === 'done' ? 'Scan complete' :
        p.status === 'cancelled' ? 'Scan cancelled' :
        p.status === 'error' ? 'Scan error' :
        `Scanning… ${pct.toFixed(1)}%`;
}

function _finishScan(data) {
    const status = document.getElementById('scanner-status');
    const progressPanel = document.getElementById('scan-progress-panel');
    const spinner = document.getElementById('scan-progress-spinner');
    const cancelBtn = document.getElementById('scan-cancel-btn');

    const count = data.threats_found || data.count || (data.threat ? 1 : 0);
    const filesScanned = data.files_scanned || 1;

    _updateProgressPanel({ ...data, percent: 100 });

    if (spinner) spinner.className = count > 0
        ? 'inline-block w-3 h-3 rounded-full bg-rose-500'
        : 'inline-block w-3 h-3 rounded-full bg-emerald-500';
    if (cancelBtn) cancelBtn.classList.add('hidden');

    status.classList.remove('hidden');
    if (data.status === 'cancelled') {
        status.innerHTML = `<div class="p-4 bg-[#16161a] border border-[#27272a] rounded-lg text-sm text-[#a1a1aa]">Scan cancelled after ${filesScanned} file${filesScanned === 1 ? '' : 's'}.</div>`;
    } else if (count > 0) {
        status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">${count} threat(s) detected in ${filesScanned} file${filesScanned === 1 ? '' : 's'}.</div>`;
    } else {
        status.innerHTML = `<div class="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">No threats detected in ${filesScanned} file${filesScanned === 1 ? '' : 's'}.</div>`;
    }

    updateScanStats({ ...data, target: data.target || document.getElementById('scan-path')?.value });
    loadThreatResults();
    loadThreatStatus();
    if (data.status !== 'cancelled') {
        addScanHistory(`Scan found ${count} threat(s)`, data.target || '');
    }
    _activeScanId = null;
}

async function cancelScan() {
    if (!_activeScanId) return;
    try {
        await apiPost(`/api/threats/scan/cancel/${_activeScanId}`);
    } catch (e) {
        console.error('Cancel failed', e);
    }
}

function updateScanStats(data) {
    const lastTime = document.getElementById('scan-last-time');
    const lastTarget = document.getElementById('scan-last-target');
    const filesCount = document.getElementById('scan-files-count');
    const threatsCount = document.getElementById('scan-threats-count');
    if (lastTime) lastTime.textContent = new Date().toLocaleString();
    if (lastTarget) lastTarget.textContent = data.target || 'Unknown';
    if (filesCount) filesCount.textContent = data.files_scanned || 0;
    if (threatsCount) threatsCount.textContent = data.threats_found || data.count || 0;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

function escapePath(path) {
    return path.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}


async function loadThreatResults() {
    try {
        const data = await apiGet('/api/threats/results');
        const container = document.getElementById('threat-results');
        document.getElementById('dash-threats').textContent = data.length;
        if (data.length === 0) {
            container.innerHTML = '<p class="text-sm text-[#71717a]">No threats detected yet.</p>';
            return;
        }
        container.innerHTML = data.map(t => {
            const info = _THREAT_EXPLANATIONS[t.threat_type] || { label: t.threat_type, what: t.description, does: 'Unknown behaviour' };
            const sev = t.severity || 'default';
            const cardSty = _SEVERITY_CARD_STYLE[sev] || _SEVERITY_CARD_STYLE.default;
            const badgeSty = _SEVERITY_BADGE_STYLE[sev] || _SEVERITY_BADGE_STYLE.default;
            const size = t.file_size ? formatFileSize(t.file_size) : null;
            const hash = t.file_hash ? t.file_hash : null;
            const displayPath = t.original_path || t.path;
            const autoQ = t.auto_quarantined;
            return `
            <div class="rounded-xl border p-5 space-y-3" style="${cardSty}">
                <div class="flex items-start justify-between gap-3">
                    <div class="flex items-center gap-2 flex-wrap">
                        <span class="text-xs font-bold px-2 py-0.5 rounded-full uppercase tracking-wide" style="${badgeSty}">${t.severity}</span>
                        <span class="text-xs font-semibold text-white">${info.label}</span>
                        ${autoQ ? '<span class="text-xs px-2 py-0.5 rounded-full border" style="background:rgba(16,185,129,0.15);color:#34d399;border-color:rgba(16,185,129,0.3)">Auto-Quarantined</span>' : ''}
                    </div>
                    <span class="text-xs text-[#71717a] shrink-0">${new Date(t.timestamp).toLocaleTimeString()}</span>
                </div>

                <div class="grid grid-cols-1 gap-2 text-sm">
                    <div class="flex gap-2">
                        <span class="text-[#71717a] shrink-0 w-16">What:</span>
                        <span class="text-[#a1a1aa]">${info.what}</span>
                    </div>
                    <div class="flex gap-2">
                        <span class="text-[#71717a] shrink-0 w-16">Risk:</span>
                        <span class="text-[#a1a1aa]">${info.does}</span>
                    </div>
                    <div class="flex gap-2">
                        <span class="text-[#71717a] shrink-0 w-16">File:</span>
                        <span class="text-xs text-[#a1a1aa] font-mono break-all">${displayPath}</span>
                    </div>
                    ${size ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-16">Size:</span><span class="text-[#a1a1aa] text-xs">${size}</span></div>` : ''}
                    ${hash ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-16">SHA256:</span><span class="text-xs text-[#71717a] font-mono break-all">${hash}</span></div>` : ''}
                </div>

                <div class="flex flex-wrap gap-2 pt-1 border-t border-white/5">
                    ${autoQ
                        ? `<button onclick="restoreFromQuarantine('${escapePath(t.path)}')" class="text-xs px-3 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20">Restore</button>`
                        : `<button onclick="quarantinePath('${escapePath(displayPath)}')" class="text-xs px-3 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 hover:bg-emerald-500/20">Quarantine</button>`
                    }
                    <button onclick="deleteThreat('${escapePath(autoQ ? t.path : displayPath)}')" class="text-xs px-3 py-1 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20">Delete</button>
                    <button onclick="ignoreThreat('${escapePath(displayPath)}')" class="text-xs px-3 py-1 rounded-lg bg-[#27272a] border border-[#3f3f46] text-[#a1a1aa] hover:text-white">Ignore</button>
                </div>
            </div>
        `}).join('');
        lucide.createIcons();
    } catch (e) {
        console.error('Threat results load failed', e);
    }
}

async function deleteThreat(path) {
    if (!await _confirm('Permanently delete this file? This cannot be undone.')) return;
    try {
        const data = await apiPost('/api/threats/delete', { path });
        if (data.success) {
            loadThreatResults();
            loadThreatStatus();
            loadAlerts();
        } else {
            _toast('Failed: ' + data.error, false);
        }
    } catch (e) {
        _toast('Error: ' + e, false);
    }
}

async function ignoreThreat(path) {
    try {
        const data = await apiPost('/api/threats/ignore', { path });
        if (data.success) {
            loadThreatResults();
            loadIgnoreList();
        } else {
            _toast('Failed: ' + data.error, false);
        }
    } catch (e) {
        _toast('Error: ' + e, false);
    }
}

async function loadIgnoreList() {
    try {
        const data = await apiGet('/api/threats/ignore/list');
        const container = document.getElementById('ignore-list');
        if (!container) return;
        if (data.ignored.length === 0) {
            container.innerHTML = '<p class="text-sm text-[#71717a]">No ignored files.</p>';
            return;
        }
        container.innerHTML = data.ignored.map(p => `
            <div class="p-3 rounded-lg bg-[#16161a] border border-[#27272a] flex items-center justify-between gap-2">
                <p class="text-xs text-[#a1a1aa] truncate flex-1">${p}</p>
                <button onclick="unignoreThreat('${escapePath(p)}')" class="text-xs text-[#71717a] hover:text-white">Remove</button>
            </div>
        `).join('');
    } catch (e) {
        console.error('Ignore list load failed', e);
    }
}

async function unignoreThreat(path) {
    try {
        const data = await apiPost('/api/threats/ignore', { path, unignore: true });
        if (data.success) {
            loadIgnoreList();
        }
    } catch (e) {
        console.error('Unignore failed', e);
    }
}

function setupDropZone() {
    const dropZone = document.getElementById('drop-zone');
    if (!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
        }, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.add('border-[#3b82f6]', 'bg-[#16161a]');
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, () => {
            dropZone.classList.remove('border-[#3b82f6]', 'bg-[#16161a]');
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        const items = e.dataTransfer.items || e.dataTransfer.files;
        if (!items || items.length === 0) return;
        const item = items[0];
        if (item.kind === 'file') {
            const file = item.getAsFile();
            if (file) {
                document.getElementById('scan-path').value = file.path || file.name;
            }
        } else if (item.getAsEntry) {
            const entry = item.getAsEntry();
            if (entry) {
                document.getElementById('scan-path').value = entry.fullPath || entry.name;
            }
        }
    });

    dropZone.addEventListener('click', () => {
        pickFile();
    });
}

async function loadIntelStatus() {
    try {
        const data = await apiGet('/api/threats/intel/status');
        const vtStatus = document.getElementById('vt-status');
        if (vtStatus) {
            vtStatus.textContent = data.virustotal_api_key_set ? 'API key set' : 'No API key';
            vtStatus.className = data.virustotal_api_key_set ? 'text-xs text-emerald-400' : 'text-xs text-slate-400';
        }
        const yaraStatus = document.getElementById('yara-status');
        if (yaraStatus) {
            yaraStatus.textContent = data.yara_available ? 'Active' : 'Not loaded';
            yaraStatus.className = data.yara_available ? 'text-xs text-emerald-400' : 'text-xs text-rose-400';
        }

        const feedData = await apiGet('/api/threats/intel/feed-status');
        const feedText = document.getElementById('feed-status-text');
        if (feedText) {
            if (feedData.last_feed_update) {
                const last = new Date(feedData.last_feed_update).toLocaleString();
                feedText.textContent = `Last update: ${last}.`;
            } else {
                feedText.textContent = 'Waiting for first update.';
            }
        }
    } catch (e) {
        console.error('Intel status load failed', e);
    }
}

async function saveVirusTotalKey() {
    const input = document.getElementById('vt-api-key');
    const key = input.value.trim();
    try {
        const data = await apiPost('/api/threats/intel/virustotal-key', { api_key: key });
        if (data.success) {
            _toast(data.set ? 'VirusTotal API key saved.' : 'VirusTotal API key cleared.');
            input.value = '';
            loadIntelStatus();
        }
    } catch (e) {
        _toast('Error saving key: ' + e, false);
    }
}

async function downloadYaraRules() {
    const btn = document.getElementById('yara-download-btn');
    btn.disabled = true;
    btn.textContent = 'Downloading...';
    try {
        const data = await apiPost('/api/threats/intel/download-yara');
        _toast(data.success ? 'YARA rules downloaded and loaded.' : 'Failed to download YARA rules.', data.success);
        loadIntelStatus();
    } catch (e) {
        _toast('Error: ' + e, false);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Download Signature-Base Rules';
    }
}

async function quarantinePath(path) {
    try {
        const data = await apiPost('/api/threats/quarantine', { path });
        if (data.success) {
            _toast('File quarantined.');
            loadThreatResults();
            loadThreatStatus();
            loadQuarantine();
            loadAlerts();
        } else {
            _toast('Failed: ' + data.error, false);
        }
    } catch (e) {
        _toast('Error: ' + e, false);
    }
}

let _quarantinePoller = null;

function _startQuarantineAutoRefresh() {
    if (_quarantinePoller) return;
    _quarantinePoller = setInterval(loadQuarantine, 3000);
}

function _stopQuarantineAutoRefresh() {
    if (_quarantinePoller) {
        clearInterval(_quarantinePoller);
        _quarantinePoller = null;
    }
}

async function loadQuarantine() {
    try {
        const data = await apiGet('/api/threats/quarantine/list');
        const container = document.getElementById('quarantine-list');
        const badge = document.getElementById('quarantine-badge');
        if (data.length > 0) {
            badge.textContent = data.length;
            badge.classList.remove('hidden');
        } else {
            badge.classList.add('hidden');
        }
        if (data.length === 0) {
            container.innerHTML = '<p class="text-sm text-[#71717a]">No quarantined files.</p>';
            return;
        }
        container.innerHTML = data.map(f => {
            const info = _THREAT_EXPLANATIONS[f.threat_type] || null;
            const sev = f.severity || 'default';
            const cardSty = _SEVERITY_CARD_STYLE[sev] || _SEVERITY_CARD_STYLE.default;
            const badgeSty = _SEVERITY_BADGE_STYLE[sev] || _SEVERITY_BADGE_STYLE.default;
            const displayName = f.original_path ? f.original_path.split('/').pop() : f.name;
            const size = f.size ? formatFileSize(f.size) : null;
            const hash = f.file_hash ? f.file_hash : null;
            const threatLabel = info ? info.label : (f.threat_type ? f.threat_type.replace(/_/g, ' ') : null);
            return `
            <div class="rounded-xl border p-5 space-y-3" style="${cardSty}">
                <div class="flex items-start justify-between gap-3 flex-wrap">
                    <div class="flex items-center gap-2 flex-wrap">
                        ${f.severity ? `<span class="text-xs font-bold px-2 py-0.5 rounded-full uppercase tracking-wide" style="${badgeSty}">${f.severity}</span>` : ''}
                        ${threatLabel ? `<span class="text-xs px-2 py-0.5 rounded-full bg-[#27272a] text-[#a1a1aa] border border-[#3f3f46]">${threatLabel}</span>` : ''}
                        <span class="text-sm font-semibold text-white truncate max-w-xs">${displayName}</span>
                    </div>
                    <span class="text-xs text-[#71717a] shrink-0">${new Date(f.timestamp).toLocaleString()}</span>
                </div>

                <div class="space-y-1.5 text-sm">
                    ${f.description ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-14">Why:</span><span class="text-[#a1a1aa]">${f.description}</span></div>` : ''}
                    ${info ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-14">Risk:</span><span class="text-[#a1a1aa]">${info.does}</span></div>` : ''}
                    ${f.original_path ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-14">Was at:</span><span class="text-xs text-[#71717a] font-mono break-all">${f.original_path}</span></div>` : ''}
                    ${size ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-14">Size:</span><span class="text-[#a1a1aa] text-xs">${size}</span></div>` : ''}
                    ${hash ? `<div class="flex gap-2"><span class="text-[#71717a] shrink-0 w-14">SHA256:</span><span class="text-xs text-[#71717a] font-mono break-all">${hash}</span></div>` : ''}
                </div>

                <div class="flex gap-2 pt-1 border-t border-white/5">
                    <button onclick="restoreFile('${escapePath(f.path)}')" class="text-xs px-3 py-1 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 hover:bg-amber-500/20">Restore</button>
                    <button onclick="deleteQuarantined('${escapePath(f.path)}')" class="text-xs px-3 py-1 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 hover:bg-rose-500/20">Delete Permanently</button>
                </div>
            </div>`;
        }).join('');
        lucide.createIcons();
    } catch (e) {
        console.error('Quarantine load failed', e);
    }
}

async function deleteQuarantined(path) {
    if (!await _confirm('Permanently delete this quarantined file? This cannot be undone.')) return;
    try {
        const data = await apiPost('/api/threats/delete', { path });
        if (data.success) {
            loadQuarantine();
        } else {
            _toast('Failed: ' + data.error, false);
        }
    } catch (e) {
        _toast('Error: ' + e, false);
    }
}

async function restoreFile(path) {
    try {
        const data = await apiPost('/api/threats/restore', { path });
        if (data.success) {
            _toast('File restored to original location.');
            loadQuarantine();
            loadThreatResults();
            loadThreatStatus();
        } else {
            _toast('Failed: ' + data.error, false);
        }
    } catch (e) {
        _toast('Error: ' + e, false);
    }
}

async function restoreFromQuarantine(path) {
    return restoreFile(path);
}

async function toggleRealtime() {
    try {
        const status = await apiGet('/api/threats/status');
        if (status.realtime_active) {
            // Show warning modal instead of immediately disabling
            const modal = document.getElementById('protection-warn-modal');
            if (modal) { modal.style.display = 'flex'; lucide.createIcons(); }
        } else {
            await apiPost('/api/threats/realtime/start');
            loadThreatStatus();
        }
    } catch (e) {
        console.error('Error toggling real-time protection:', e);
    }
}

async function confirmDisableProtection() {
    document.getElementById('protection-warn-modal').style.display = 'none';
    try {
        await apiPost('/api/threats/realtime/stop');
        loadThreatStatus();
    } catch(e) { console.error(e); }
}

function cancelDisableProtection() {
    document.getElementById('protection-warn-modal').style.display = 'none';
}

async function checkUrl() {
    const input = document.getElementById('check-url-input');
    const url = input.value.trim();
    if (!url) return _toast('Enter a URL', false);
    const status = document.getElementById('network-threat-status');
    const btn = document.getElementById('check-url-btn');
    btn.disabled = true;
    status.classList.remove('hidden');
    status.innerHTML = '<div class="p-4 bg-slate-800/50 rounded-lg text-sm text-slate-300">Checking URLhaus...</div>';

    try {
        const data = await apiPost('/api/threats/intel/check-url', { url });
        if (data.success && data.result && !data.result.not_found && !data.result.error) {
            status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400"><strong>Malicious URL detected</strong><br>${data.result.threat || ''}<br>Payloads: ${data.result.payloads}<br><a href="${data.result.permalink}" target="_blank" class="text-emerald-400 hover:underline">View on URLhaus</a></div>`;
        } else {
            status.innerHTML = `<div class="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">URL not found in URLhaus. Likely clean.</div>`;
        }
    } catch (e) {
        status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Error: ${e}</div>`;
    } finally {
        btn.disabled = false;
    }
}

async function checkHost() {
    const input = document.getElementById('check-host-input');
    const host = input.value.trim();
    if (!host) return _toast('Enter an IP or domain', false);
    const status = document.getElementById('network-threat-status');
    const btn = document.getElementById('check-host-btn');
    btn.disabled = true;
    status.classList.remove('hidden');
    status.innerHTML = '<div class="p-4 bg-slate-800/50 rounded-lg text-sm text-slate-300">Checking URLhaus and ThreatFox...</div>';

    try {
        const data = await apiPost('/api/threats/intel/check-host', { host });
        let html = '';
        if (data.urlhaus && !data.urlhaus.not_found && !data.urlhaus.error) {
            html += `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400 mb-2"><strong>URLhaus:</strong> ${data.urlhaus.url_count} malicious URL(s) linked to ${host}. <a href="${data.urlhaus.permalink}" target="_blank" class="text-emerald-400 hover:underline">View</a></div>`;
        }
        if (data.threatfox && !data.threatfox.not_found && !data.threatfox.error) {
            html += `<div class="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg text-sm text-amber-400"><strong>ThreatFox:</strong> ${data.threatfox.malware} (${data.threatfox.threat_type})</div>`;
        }
        if (!html) {
            html = `<div class="p-4 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-sm text-emerald-400">Host not found in threat intelligence feeds. Likely clean.</div>`;
        }
        status.innerHTML = html;
    } catch (e) {
        status.innerHTML = `<div class="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-sm text-rose-400">Error: ${e}</div>`;
    } finally {
        btn.disabled = false;
    }
}

async function checkVulns() {
    const input = document.getElementById('vuln-product-input');
    const product = input.value.trim();
    if (!product) return _toast('Enter a product name', false);
    await _runVulnCheck({ product });
}

async function checkRunningVulns() {
    await _runVulnCheck({ product: 'running' });
}

async function _runVulnCheck(body) {
    const container = document.getElementById('vuln-results');
    const btn = document.getElementById(body.product === 'running' ? 'vuln-running-btn' : 'vuln-check-btn');
    btn.disabled = true;
    container.innerHTML = '<p class="text-sm text-slate-400">Checking CISA KEV catalog...</p>';

    try {
        const data = await apiPost('/api/threats/intel/vulns', body);
        if (data.success) {
            renderVulnResults(data.matches);
        } else {
            container.innerHTML = `<p class="text-sm text-rose-400">Error: ${data.error}</p>`;
        }
    } catch (e) {
        container.innerHTML = `<p class="text-sm text-rose-400">Error: ${e}</p>`;
    } finally {
        btn.disabled = false;
    }
}

function renderVulnResults(matches) {
    const container = document.getElementById('vuln-results');
    if (matches.length === 0) {
        container.innerHTML = '<p class="text-sm text-emerald-400">No known exploited vulnerabilities found.</p>';
        return;
    }
    container.innerHTML = matches.map(v => `
        <div class="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20">
            <div class="flex items-center gap-2 mb-1">
                <span class="text-xs font-bold text-amber-400 px-1.5 py-0.5 rounded bg-slate-800">${v.cveID}</span>
                <span class="text-xs text-slate-400">${v.vendorProject} · ${v.product}</span>
                ${v._matched_process ? `<span class="text-xs text-rose-400">process: ${v._matched_process}</span>` : ''}
            </div>
            <p class="text-sm text-white">${v.vulnerabilityName}</p>
            <p class="text-xs text-slate-400 mt-1">${v.dateAdded || ''} · Due: ${v.dueDate || ''}</p>
            <p class="text-xs text-slate-500 mt-1">${v.requiredAction || ''}</p>
        </div>
    `).join('');
}

async function updateFeeds() {
    const btn = document.getElementById('update-feeds-btn');
    btn.disabled = true;
    btn.textContent = 'Updating...';
    try {
        const data = await apiPost('/api/threats/intel/update-feeds');
        _toast(data.success ? 'CISA KEV feed updated.' : 'Failed to update feed.', data.success);
    } catch (e) {
        _toast('Error: ' + e, false);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Update CISA Feed';
    }
}

// License management
function setLicenseMessage(text, type = 'info') {
    const el = document.getElementById('license-message');
    const colors = {
        success: 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400',
        error: 'bg-rose-500/10 border-rose-500/20 text-rose-400',
        info: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
    };
    el.className = `p-4 rounded-lg border text-sm ${colors[type] || colors.info}`;
    el.textContent = text;
    el.classList.remove('hidden');
}

async function loadLicense() {
    try {
        const data = await apiGet('/api/license/status');
        const statusBadge = document.getElementById('license-status-badge');
        const keyInput = document.getElementById('license-key-input');
        const keyDisplay = document.getElementById('license-key-display');
        const serverInput = document.getElementById('license-server-input');

        if (data.server_url) {
            serverInput.value = data.server_url;
        }

        if (!data.license_key) {
            statusBadge.textContent = 'No License';
            statusBadge.className = 'badge badge-medium';
            document.getElementById('license-tier').textContent = 'Free / Trial';
            document.getElementById('license-expires').textContent = 'N/A';
            document.getElementById('license-devices').textContent = 'N/A';
            document.getElementById('license-activated').textContent = 'Not activated';
            keyDisplay.classList.add('hidden');
            return;
        }

        keyInput.value = data.license_key;
        keyDisplay.textContent = `Key: ${data.license_key}`;
        keyDisplay.classList.remove('hidden');

        document.getElementById('license-tier').textContent = data.tier || 'Unknown';
        document.getElementById('license-expires').textContent = data.expires_at
            ? new Date(data.expires_at).toLocaleDateString()
            : 'Never';
        document.getElementById('license-devices').textContent = `${data.device_count || 0} / ${data.max_devices || 1}`;
        document.getElementById('license-activated').textContent = data.activated ? 'Active' : 'Inactive';

        if (data.activated && data.is_valid) {
            statusBadge.textContent = 'Active';
            statusBadge.className = 'badge badge-clean';
        } else if (data.activated) {
            statusBadge.textContent = 'Invalid';
            statusBadge.className = 'badge badge-critical';
        } else {
            statusBadge.textContent = 'Inactive';
            statusBadge.className = 'badge badge-medium';
        }
    } catch (e) {
        console.error('License load failed', e);
    }
}

async function saveLicenseKey() {
    const key = document.getElementById('license-key-input').value.trim();
    const serverUrl = document.getElementById('license-server-input').value.trim();
    if (!key) return;
    try {
        const data = await apiPost('/api/license/set-key', { license_key: key, server_url: serverUrl });
        if (data.success) {
            setLicenseMessage('License key saved.', 'success');
            loadLicense();
        } else {
            setLicenseMessage(data.error || 'Failed to save key.', 'error');
        }
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

async function activateLicense() {
    try {
        const data = await apiPost('/api/license/activate');
        if (data.success) {
            setLicenseMessage('License activated successfully.', 'success');
            loadLicense();
        } else {
            setLicenseMessage(data.error || 'Activation failed.', 'error');
        }
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

async function validateLicense() {
    try {
        const data = await apiPost('/api/license/validate');
        if (data.valid) {
            setLicenseMessage('License is valid.', 'success');
        } else {
            setLicenseMessage(data.error || 'License is not valid.', 'error');
        }
        loadLicense();
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

async function deactivateLicense() {
    try {
        const data = await apiPost('/api/license/deactivate');
        if (data.success) {
            setLicenseMessage('License deactivated.', 'info');
            loadLicense();
        } else {
            setLicenseMessage(data.error || 'Deactivation failed.', 'error');
        }
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

async function openCheckout() {
    const email = document.getElementById('checkout-email').value.trim();
    const tier = document.getElementById('checkout-tier').value;
    if (!email) {
        setLicenseMessage('Please enter an email for checkout.', 'error');
        return;
    }
    try {
        const data = await apiPost('/api/license/checkout', { email, tier });
        if (data.url) {
            window.open(data.url, '_blank');
        } else {
            setLicenseMessage(data.error || 'Checkout unavailable.', 'error');
        }
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

async function openCustomerPortal() {
    const stripeCustomerId = document.getElementById('customer-portal-id').value.trim();
    if (!stripeCustomerId) {
        setLicenseMessage('Please enter a Stripe customer ID.', 'error');
        return;
    }
    try {
        const data = await apiPost('/api/license/customer-portal', { stripe_customer_id: stripeCustomerId });
        if (data.url) {
            window.open(data.url, '_blank');
        } else {
            setLicenseMessage(data.error || 'Portal unavailable.', 'error');
        }
    } catch (e) {
        setLicenseMessage('Error: ' + e, 'error');
    }
}

function downloadApp(platform) {
    const urls = {
        mac: 'https://sentinel.example.com/download/latest/mac-arm64.dmg',
        windows: 'https://sentinel.example.com/download/latest/windows-x64.exe',
        linux: 'https://sentinel.example.com/download/latest/linux-x64.AppImage',
    };
    window.open(urls[platform] || urls.mac, '_blank');
}

// ── Beta Program & Update functions ──────────────────────────────────────────

async function loadBetaConfig() {
    try {
        const data = await apiGet('/api/beta/config');
        const badge = document.getElementById('beta-status-badge');
        const info = document.getElementById('beta-info');
        if (data.configured) {
            if (badge) { badge.textContent = 'Connected'; badge.style.cssText = 'background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.3)'; }
            if (info) info.classList.remove('hidden');
            const urlEl = document.getElementById('beta-admin-url');
            const keyEl = document.getElementById('beta-key-input');
            if (urlEl) urlEl.value = data.admin_url;
            if (keyEl) keyEl.value = data.beta_key;
            document.getElementById('beta-machine-id').textContent = data.machine_id;
            document.getElementById('beta-version').textContent = data.version;
            document.getElementById('beta-admin-url-display').textContent = data.admin_url;
        } else {
            if (badge) { badge.textContent = 'Not configured'; badge.style.cssText = ''; }
        }
        document.getElementById('about-version').textContent = data.version || 'v1.0.0-beta';
        await checkForUpdates();
    } catch (e) {
        console.error('Beta config load failed', e);
    }
}

async function configureBeta() {
    const admin_url = document.getElementById('beta-admin-url').value.trim();
    const beta_key = document.getElementById('beta-key-input').value.trim();
    const statusEl = document.getElementById('beta-configure-status');
    statusEl.classList.remove('hidden');
    statusEl.style.color = '#a1a1aa';
    statusEl.textContent = 'Connecting…';
    try {
        const data = await apiPost('/api/beta/configure', { admin_url, beta_key });
        if (data.success) {
            statusEl.style.color = '#34d399';
            statusEl.textContent = `Activated! ${data.label ? '(' + data.label + ')' : ''}`;
            await loadBetaConfig();
        } else {
            statusEl.style.color = '#f87171';
            statusEl.textContent = data.error || 'Failed to activate.';
        }
    } catch (e) {
        statusEl.style.color = '#f87171';
        statusEl.textContent = 'Error: ' + e;
    }
}

async function submitFeedback() {
    const type = document.getElementById('feedback-type').value;
    const message = document.getElementById('feedback-message').value.trim();
    const includeDiag = document.getElementById('include-diagnostics').checked;
    const statusEl = document.getElementById('feedback-status');
    const btn = document.getElementById('feedback-submit-btn');

    if (!message) {
        statusEl.className = 'text-sm p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400';
        statusEl.textContent = 'Please enter a message before sending.';
        statusEl.classList.remove('hidden');
        return;
    }

    // Get beta config to find admin URL + key
    let adminUrl = '', betaKey = '', machineId = '';
    try {
        const cfg = await apiGet('/api/beta/config');
        adminUrl = cfg.admin_url || '';
        betaKey = cfg.beta_key || '';
        machineId = cfg.machine_id || '';
    } catch(e) {}

    if (!adminUrl) {
        statusEl.className = 'text-sm p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400';
        statusEl.textContent = 'No admin server configured. Go to Settings → Beta Program first.';
        statusEl.classList.remove('hidden');
        return;
    }

    let diagnostics = {};
    if (includeDiag) {
        try {
            const [sys, threats] = await Promise.all([
                apiGet('/api/system'),
                apiGet('/api/threats/status'),
            ]);
            diagnostics = {
                platform: sys.platform,
                cpu_percent: sys.cpu?.percent,
                memory_percent: sys.memory?.percent,
                disk_percent: sys.disk?.percent,
                realtime_active: threats.realtime_active,
                quarantine_count: threats.quarantine_count,
            };
        } catch(e) {}
    }

    btn.disabled = true;
    statusEl.className = 'text-sm p-3 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400';
    statusEl.textContent = 'Sending…';
    statusEl.classList.remove('hidden');

    try {
        const resp = await fetch(`${adminUrl}/api/beta/feedback`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, message, beta_key: betaKey, machine_id: machineId, diagnostics }),
        });
        const data = await resp.json();
        if (data.success) {
            statusEl.className = 'text-sm p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400';
            statusEl.textContent = 'Sent! Thank you for your feedback.';
            document.getElementById('feedback-message').value = '';
        } else {
            statusEl.className = 'text-sm p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400';
            statusEl.textContent = data.error || 'Failed to send. Check your admin URL in Settings.';
        }
    } catch(e) {
        statusEl.className = 'text-sm p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400';
        statusEl.textContent = 'Could not reach admin server. Check your connection.';
    } finally {
        btn.disabled = false;
    }
}

async function checkForUpdates() {
    try {
        const data = await apiGet('/api/beta/update-check');
        if (!data.update_available) return;
        const toast = document.getElementById('update-toast');
        if (!toast) return;
        document.getElementById('update-toast-version').textContent =
            `v${data.latest_version} is available (you have ${data.current_version})`;
        document.getElementById('update-toast-notes').textContent = data.release_notes || '';
        const link = document.getElementById('update-toast-link');
        if (data.download_url) { link.href = data.download_url; link.style.display = 'inline-block'; }
        else link.style.display = 'none';
        toast.style.display = 'block';
    } catch (e) {
        // silently ignore if admin server not configured
    }
}

function installUpdateNow() {
    if (window.electronAPI && window.electronAPI.installUpdateNow) {
        window.electronAPI.installUpdateNow();
    }
}

// ── In-app update panel controller ───────────────────────────────────────────
const _updatePanel = {
    show(title, version) {
        const p = document.getElementById('update-panel');
        if (!p) return;
        document.getElementById('update-panel-title').textContent = title;
        document.getElementById('update-panel-version').textContent = version ? `Version ${version}` : '';
        p.style.display = 'block';
    },
    setProgress(progress) {
        const wrap = document.getElementById('update-panel-progress-wrap');
        if (wrap) wrap.style.display = 'block';
        const pct = Math.round(progress.percent || 0);
        const bar = document.getElementById('update-panel-bar');
        const pctEl = document.getElementById('update-panel-pct');
        const speedEl = document.getElementById('update-panel-speed');
        const etaEl = document.getElementById('update-panel-eta');
        if (bar) bar.style.width = pct + '%';
        if (pctEl) pctEl.textContent = pct + '%';
        if (speedEl && progress.bytesPerSecond) {
            const mbps = (progress.bytesPerSecond / 1024 / 1024).toFixed(1);
            speedEl.textContent = mbps + ' MB/s';
        }
        if (etaEl && progress.total && progress.transferred) {
            const remaining = progress.total - progress.transferred;
            const secs = Math.round(remaining / (progress.bytesPerSecond || 1));
            etaEl.textContent = secs > 0 ? `~${secs}s remaining` : 'almost done…';
        }
        document.getElementById('update-panel-title').textContent = 'Downloading Update…';
    },
    setReady(version) {
        document.getElementById('update-panel-title').textContent = 'Update Ready';
        document.getElementById('update-panel-version').textContent = version ? `Version ${version} downloaded` : 'Downloaded';
        const bar = document.getElementById('update-panel-bar');
        if (bar) { bar.style.width = '100%'; bar.style.background = '#22c55e'; bar.style.animation = 'none'; }
        const pctEl = document.getElementById('update-panel-pct');
        if (pctEl) pctEl.textContent = '100%';
        const statusEl = document.getElementById('update-panel-status');
        if (statusEl) { statusEl.textContent = 'Complete'; statusEl.style.color = '#22c55e'; }
        const etaEl = document.getElementById('update-panel-eta');
        if (etaEl) etaEl.textContent = '';
        const btn = document.getElementById('update-panel-install-btn');
        if (btn) btn.style.display = 'flex';
    },
    setError(msg) {
        document.getElementById('update-panel-title').textContent = 'Update Failed';
        document.getElementById('update-panel-version').textContent = msg || 'Check your connection and try again.';
    },
};

function _injectUpdateAlert(info, downloaded) {
    const version = (info && info.version) ? `v${info.version}` : 'a new version';
    // Show the floating panel
    if (downloaded) {
        _updatePanel.setReady(version);
    } else {
        _updatePanel.show('Update Available', version);
    }
    // Also add to bell dropdown
    const alert = {
        id: 'update-' + Date.now(),
        source: 'update',
        severity: 'low',
        label: downloaded ? `Update ready: ${version}` : `Update available: ${version}`,
        message: downloaded
            ? 'Downloaded. Click "Install & Restart" in the bottom-right panel.'
            : 'Downloading in the background — progress shown in bottom-right.',
        risk: 'None — this is a system update notification.',
        timestamp: new Date().toISOString(),
        read: false,
    };
    _cachedAlerts = [alert, ..._cachedAlerts.filter(a => a.source !== 'update')];
    const unread = _cachedAlerts.filter(a => !a.read).length;
    const bellBadge = document.getElementById('bell-badge');
    if (bellBadge) { bellBadge.textContent = unread; bellBadge.style.display = 'flex'; }
    _renderAlertDropdown();
    _toast(downloaded ? `✓ Update ${version} ready — click Install & Restart` : `↓ Update ${version} downloading…`, true, 5000);
}

// Initialize
async function _initAll() {
    // Step 0: connect to engine
    await initEngine();

    // Step 1: load threat intelligence + alerts
    _loader.step(1);
    await Promise.all([loadAlerts(), loadIntelStatus()]);

    // Step 2: start real-time protection + load threat status
    _loader.step(2);
    await apiPost('/api/threats/realtime/start').catch(() => {});
    await loadThreatStatus();

    // Step 3: load system + network data
    _loader.step(3);
    await Promise.all([loadSystem(), loadSubnet(), loadDevices()]);

    // Step 4: load remaining interface data
    _loader.step(4);
    await Promise.all([loadLicense(), loadBetaConfig(), loadIgnoreList()]);

    // Set up refresh intervals now that initial data is loaded
    setInterval(loadAlerts, 10000);
    setInterval(loadThreatStatus, 15000);
    setInterval(loadSystem, 10000);
    setInterval(loadIntelStatus, 60000);
    setInterval(loadLicense, 60000);
    setInterval(checkForUpdates, 120000);

    setupDropZone();
    lucide.createIcons();

    // Wire up auto-updater notifications → bell dropdown
    if (window.electronAPI) {
        if (window.electronAPI.onUpdateAvailable)
            window.electronAPI.onUpdateAvailable((info) => _injectUpdateAlert(info, false));
        if (window.electronAPI.onUpdateProgress)
            window.electronAPI.onUpdateProgress((progress) => { _updatePanel.show('Downloading Update…', ''); _updatePanel.setProgress(progress); });
        if (window.electronAPI.onUpdateDownloaded)
            window.electronAPI.onUpdateDownloaded((info) => _injectUpdateAlert(info, true));
        if (window.electronAPI.onUpdateError)
            window.electronAPI.onUpdateError((msg) => _updatePanel.setError(msg));
    }

    // All data ready — fade out loader into a fully populated dashboard
    _loader.hide();
}
_initAll();
