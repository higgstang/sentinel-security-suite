"""
Sentinel Super User Admin Server
Runs locally on the developer's machine (port 18082).
Manages beta keys, connected clients, and update releases.
"""

import hashlib
import json
import os
import secrets
import time
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, request, render_template_string, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Storage paths ──────────────────────────────────────────────────────────────
_BASE = os.path.dirname(os.path.abspath(__file__))
_DATA_DIR = os.path.join(_BASE, "admin_data")
os.makedirs(_DATA_DIR, exist_ok=True)

_KEYS_FILE       = os.path.join(_DATA_DIR, "beta_keys.json")
_CLIENTS_FILE    = os.path.join(_DATA_DIR, "clients.json")
_UPDATES_FILE    = os.path.join(_DATA_DIR, "updates.json")
_ADMIN_KEY_FILE  = os.path.join(_DATA_DIR, "admin_key.txt")
_FEEDBACK_FILE   = os.path.join(_DATA_DIR, "feedback.json")

# ── Admin key (protects the admin endpoints) ───────────────────────────────────
def _get_admin_key():
    if os.path.exists(_ADMIN_KEY_FILE):
        with open(_ADMIN_KEY_FILE) as f:
            return f.read().strip()
    key = secrets.token_hex(24)
    with open(_ADMIN_KEY_FILE, "w") as f:
        f.write(key)
    print(f"\n{'='*60}")
    print(f"  ADMIN KEY (save this): {key}")
    print(f"{'='*60}\n")
    return key

ADMIN_KEY = _get_admin_key()

# ── Heartbeat timeout: clients not seen for > 5 min are marked offline ─────────
_HEARTBEAT_TIMEOUT = 300

# ── File helpers ───────────────────────────────────────────────────────────────
_lock = threading.Lock()

def _load(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass
    return default

def _save(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

# ── Auth helper ────────────────────────────────────────────────────────────────
def _require_admin():
    key = request.headers.get("X-Admin-Key") or request.args.get("admin_key", "")
    if key != ADMIN_KEY:
        abort(403)

# ══════════════════════════════════════════════════════════════════════════════
# BETA KEY MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def _load_keys():
    return _load(_KEYS_FILE, {})

def _save_keys(keys):
    _save(_KEYS_FILE, keys)

def _generate_beta_key(label="", max_uses=1):
    raw = secrets.token_hex(10).upper()
    key = f"SENT-{raw[:5]}-{raw[5:10]}-{raw[10:]}"
    keys = _load_keys()
    keys[key] = {
        "label": label,
        "max_uses": max_uses,
        "uses": 0,
        "active": True,
        "created": datetime.now(timezone.utc).isoformat(),
        "activations": [],
    }
    _save_keys(keys)
    return key


@app.route("/admin/keys", methods=["GET"])
def admin_list_keys():
    _require_admin()
    return jsonify(list(_load_keys().values()) and _load_keys())


@app.route("/admin/keys/generate", methods=["POST"])
def admin_generate_key():
    _require_admin()
    data = request.json or {}
    key = _generate_beta_key(
        label=data.get("label", ""),
        max_uses=int(data.get("max_uses", 1)),
    )
    return jsonify({"success": True, "key": key})


@app.route("/admin/keys/<key>/revoke", methods=["POST"])
def admin_revoke_key(key):
    _require_admin()
    keys = _load_keys()
    if key not in keys:
        return jsonify({"success": False, "error": "Key not found"}), 404
    keys[key]["active"] = False
    _save_keys(keys)
    return jsonify({"success": True})


@app.route("/admin/keys/<key>/delete", methods=["POST"])
def admin_delete_key(key):
    _require_admin()
    keys = _load_keys()
    if key in keys:
        del keys[key]
        _save_keys(keys)
    return jsonify({"success": True})


# ── Public endpoint: clients validate beta keys ────────────────────────────────
@app.route("/api/beta/validate", methods=["POST"])
def api_validate_beta_key():
    data = request.json or {}
    key = (data.get("key") or "").strip().upper()
    machine_id = data.get("machine_id", "")
    hostname = data.get("hostname", "")

    with _lock:
        keys = _load_keys()
        if key not in keys:
            return jsonify({"valid": False, "error": "Invalid beta key"})
        entry = keys[key]
        if not entry["active"]:
            return jsonify({"valid": False, "error": "Key revoked"})
        # Allow same machine to re-validate
        machines = [a["machine_id"] for a in entry["activations"]]
        if machine_id not in machines:
            if entry["uses"] >= entry["max_uses"]:
                return jsonify({"valid": False, "error": "Key usage limit reached"})
            entry["uses"] += 1
            entry["activations"].append({
                "machine_id": machine_id,
                "hostname": hostname,
                "activated_at": datetime.now(timezone.utc).isoformat(),
            })
        _save_keys(keys)

    return jsonify({"valid": True, "label": entry["label"]})


# ══════════════════════════════════════════════════════════════════════════════
# CLIENT HEARTBEAT / TELEMETRY
# ══════════════════════════════════════════════════════════════════════════════

def _load_clients():
    return _load(_CLIENTS_FILE, {})

def _save_clients(clients):
    _save(_CLIENTS_FILE, clients)


@app.route("/api/client/heartbeat", methods=["POST"])
def api_client_heartbeat():
    """Called by each client every 60s to report status."""
    data = request.json or {}
    machine_id = data.get("machine_id", "")
    if not machine_id:
        return jsonify({"success": False, "error": "machine_id required"}), 400

    with _lock:
        clients = _load_clients()
        existing = clients.get(machine_id, {})
        clients[machine_id] = {
            "machine_id": machine_id,
            "hostname": data.get("hostname", existing.get("hostname", "")),
            "platform": data.get("platform", existing.get("platform", "")),
            "beta_key": data.get("beta_key", existing.get("beta_key", "")),
            "version": data.get("version", existing.get("version", "")),
            "cpu_percent": data.get("cpu_percent", 0),
            "memory_percent": data.get("memory_percent", 0),
            "disk_percent": data.get("disk_percent", 0),
            "threats_found": data.get("threats_found", existing.get("threats_found", 0)),
            "files_scanned": data.get("files_scanned", existing.get("files_scanned", 0)),
            "quarantine_count": data.get("quarantine_count", existing.get("quarantine_count", 0)),
            "realtime_active": data.get("realtime_active", False),
            "uptime_seconds": data.get("uptime_seconds", 0),
            "last_seen": datetime.now(timezone.utc).isoformat(),
            "first_seen": existing.get("first_seen", datetime.now(timezone.utc).isoformat()),
            "ip": request.remote_addr,
        }
        _save_clients(clients)

    # Return current update info so client can show notification
    updates = _load(_UPDATES_FILE, {})
    return jsonify({
        "success": True,
        "latest_version": updates.get("latest_version", ""),
        "update_url": updates.get("download_url", ""),
        "update_notes": updates.get("release_notes", ""),
        "update_required": updates.get("required", False),
    })


@app.route("/admin/clients", methods=["GET"])
def admin_list_clients():
    _require_admin()
    clients = _load_clients()
    now = time.time()
    result = []
    for c in clients.values():
        last = c.get("last_seen", "")
        try:
            last_ts = datetime.fromisoformat(last.replace("Z", "+00:00")).timestamp()
            online = (now - last_ts) < _HEARTBEAT_TIMEOUT
        except Exception:
            online = False
        result.append({**c, "online": online})
    result.sort(key=lambda x: x.get("last_seen", ""), reverse=True)
    return jsonify(result)


# ══════════════════════════════════════════════════════════════════════════════
# UPDATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/updates/latest", methods=["GET"])
def api_latest_update():
    """Public endpoint — clients poll this to check for updates."""
    return jsonify(_load(_UPDATES_FILE, {
        "latest_version": "",
        "release_notes": "",
        "download_url": "",
        "required": False,
        "published_at": "",
    }))


@app.route("/admin/updates/publish", methods=["POST"])
def admin_publish_update():
    _require_admin()
    data = request.json or {}
    version = data.get("version", "").strip()
    if not version:
        return jsonify({"success": False, "error": "version required"}), 400
    update = {
        "latest_version": version,
        "release_notes": data.get("release_notes", ""),
        "download_url": data.get("download_url", ""),
        "download_url_mac": data.get("download_url_mac", ""),
        "download_url_win": data.get("download_url_win", ""),
        "required": bool(data.get("required", False)),
        "published_at": datetime.now(timezone.utc).isoformat(),
    }
    _save(_UPDATES_FILE, update)
    return jsonify({"success": True, "update": update})


@app.route("/admin/updates", methods=["GET"])
def admin_get_update():
    _require_admin()
    return jsonify(_load(_UPDATES_FILE, {}))


@app.route("/admin/stats", methods=["GET"])
def admin_stats():
    _require_admin()
    clients = _load_clients()
    now = time.time()
    online, offline = [], []
    total_threats = total_scanned = total_quarantine = 0
    versions = {}
    platforms = {}
    for c in clients.values():
        last = c.get("last_seen", "")
        try:
            last_ts = datetime.fromisoformat(last.replace("Z", "+00:00")).timestamp()
            is_online = (now - last_ts) < _HEARTBEAT_TIMEOUT
        except Exception:
            is_online = False
        (online if is_online else offline).append(c)
        total_threats   += c.get("threats_found", 0)
        total_scanned   += c.get("files_scanned", 0)
        total_quarantine+= c.get("quarantine_count", 0)
        v = c.get("version", "unknown")
        versions[v] = versions.get(v, 0) + 1
        p = (c.get("platform") or "unknown").split("-")[0].split("(")[0].strip()
        if "mac" in p.lower() or "darwin" in p.lower(): p = "macOS"
        elif "win" in p.lower(): p = "Windows"
        elif "linux" in p.lower(): p = "Linux"
        else: p = "Other"
        platforms[p] = platforms.get(p, 0) + 1
    keys = _load_keys()
    active_keys   = sum(1 for k in keys.values() if k["active"])
    revoked_keys  = sum(1 for k in keys.values() if not k["active"])
    total_activations = sum(k["uses"] for k in keys.values())
    return jsonify({
        "total_clients": len(clients),
        "online": len(online),
        "offline": len(offline),
        "total_threats": total_threats,
        "total_scanned": total_scanned,
        "total_quarantine": total_quarantine,
        "versions": versions,
        "platforms": platforms,
        "active_keys": active_keys,
        "revoked_keys": revoked_keys,
        "total_activations": total_activations,
        "realtime_active": sum(1 for c in clients.values() if c.get("realtime_active")),
        "avg_cpu": round(sum(c.get("cpu_percent",0) for c in clients.values()) / max(len(clients),1), 1),
        "avg_mem": round(sum(c.get("memory_percent",0) for c in clients.values()) / max(len(clients),1), 1),
        "avg_disk": round(sum(c.get("disk_percent",0) for c in clients.values()) / max(len(clients),1), 1),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN UI (served at /admin)
# ══════════════════════════════════════════════════════════════════════════════

_PANEL_FILE = os.path.join(_BASE, "admin_panel.html")

def _load_panel():
    if os.path.exists(_PANEL_FILE):
        with open(_PANEL_FILE, encoding="utf-8") as f:
            return f.read()
    return "<h1>admin_panel.html not found</h1>"

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel Admin</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*{box-sizing:border-box}
body{background:#07070a;color:#e4e4e7;font-family:system-ui,sans-serif;margin:0}
.sidebar{position:fixed;left:0;top:0;width:220px;height:100vh;background:#0e0e12;border-right:1px solid #1c1c21;display:flex;flex-direction:column;padding:20px 0;z-index:100}
.sidebar-logo{padding:0 20px 20px;border-bottom:1px solid #1c1c21;display:flex;align-items:center;gap:10px}
.sidebar-logo h1{font-size:15px;font-weight:700;color:#fff;margin:0}
.sidebar-logo p{font-size:10px;color:#71717a;margin:0}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;font-size:13px;font-weight:500;color:#71717a;cursor:pointer;border:none;background:none;width:100%;text-align:left;border-radius:0;transition:.15s}
.nav-item:hover{color:#fff;background:#1c1c21}
.nav-item.active{color:#fff;background:#1c1c21;border-right:2px solid #3b82f6}
.main{margin-left:220px;padding:28px;min-height:100vh}
.card{background:#111113;border:1px solid #1c1c21;border-radius:14px;padding:20px}
.metric-card{background:#111113;border:1px solid #1c1c21;border-radius:14px;padding:18px 20px}
.metric-val{font-size:28px;font-weight:800;color:#fff;margin:4px 0}
.metric-label{font-size:11px;color:#71717a;font-weight:500;text-transform:uppercase;letter-spacing:.06em}
.metric-sub{font-size:11px;color:#52525b;margin-top:2px}
.gauge-bar{height:6px;border-radius:9999px;background:#1c1c21;overflow:hidden;margin-top:8px}
.gauge-fill{height:100%;border-radius:9999px;transition:.6s}
.badge-on{background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.3);border-radius:9999px;font-size:10px;padding:2px 8px;font-weight:600}
.badge-off{background:rgba(113,113,122,.12);color:#52525b;border:1px solid rgba(113,113,122,.2);border-radius:9999px;font-size:10px;padding:2px 8px}
.btn{padding:7px 14px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;border:none;transition:.15s;display:inline-flex;align-items:center;gap:5px}
.btn-primary{background:#3b82f6;color:#fff}
.btn-primary:hover{background:#2563eb}
.btn-danger{background:rgba(239,68,68,.12);color:#f87171;border:1px solid rgba(239,68,68,.25)}
.btn-danger:hover{background:rgba(239,68,68,.22)}
.btn-secondary{background:#1c1c21;color:#a1a1aa;border:1px solid #27272a}
.btn-secondary:hover{color:#fff;background:#27272a}
.btn-green{background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(16,185,129,.3)}
.btn-green:hover{background:rgba(16,185,129,.25)}
input,textarea,select{background:#0e0e12;border:1px solid #27272a;border-radius:8px;color:#e4e4e7;padding:8px 12px;font-size:13px;width:100%;outline:none}
input:focus,textarea:focus,select:focus{border-color:#3b82f6}
.table-row{display:grid;border-bottom:1px solid #1c1c21;padding:10px 12px;font-size:12px;align-items:center;transition:.1s}
.table-row:hover{background:#16161a}
.table-header{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:#52525b;padding:8px 12px;border-bottom:1px solid #1c1c21}
.section-title{font-size:16px;font-weight:700;color:#fff;margin:0 0 4px}
.section-sub{font-size:12px;color:#71717a;margin:0 0 16px}
.search-bar{background:#0e0e12;border:1px solid #27272a;border-radius:8px;padding:7px 12px;font-size:12px;color:#e4e4e7;width:260px;outline:none}
.search-bar:focus{border-color:#3b82f6}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:#0e0e12}::-webkit-scrollbar-thumb{background:#27272a;border-radius:4px}
.progress-ring{transform:rotate(-90deg)}
.tab-panel{display:none}.tab-panel.active{display:block}
</style>
</head>
<body>

<!-- Sidebar -->
<aside class="sidebar">
  <div class="sidebar-logo">
    <svg width="22" height="22" fill="none" viewBox="0 0 24 24"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z" fill="#3b82f6" fill-opacity=".2" stroke="#3b82f6" stroke-width="1.5"/></svg>
    <div><h1>Sentinel</h1><p>Admin Panel</p></div>
  </div>
  <nav style="flex:1;padding:12px 0;overflow-y:auto">
    <button class="nav-item active" id="nav-overview" onclick="showPage('overview')">
      <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
      Overview
    </button>
    <button class="nav-item" id="nav-clients" onclick="showPage('clients')">
      <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><circle cx="9" cy="7" r="4"/><path d="M3 21v-2a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v2"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/><path d="M21 21v-2a4 4 0 0 0-3-3.87"/></svg>
      Connected Clients
      <span id="online-pill" style="margin-left:auto;font-size:10px;padding:1px 6px;border-radius:9999px;background:rgba(16,185,129,.15);color:#34d399;display:none">0</span>
    </button>
    <button class="nav-item" id="nav-keys" onclick="showPage('keys')">
      <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>
      Beta Keys
    </button>
    <button class="nav-item" id="nav-updates" onclick="showPage('updates')">
      <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
      Updates
    </button>
  </nav>
  <div style="padding:16px 20px;border-top:1px solid #1c1c21">
    <p id="auth-status" style="font-size:11px;color:#52525b">Not authenticated</p>
  </div>
</aside>

<!-- Main -->
<main class="main">

  <!-- Auth bar -->
  <div id="auth-bar" style="background:#111113;border:1px solid #27272a;border-radius:12px;padding:14px 18px;margin-bottom:20px;display:flex;align-items:center;gap:10px">
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="#71717a" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    <input type="password" id="admin-key-input" placeholder="Paste your admin key to unlock…" style="flex:1;background:none;border:none;padding:0;font-size:13px;color:#e4e4e7">
    <button class="btn btn-primary" onclick="setAdminKey()">Unlock</button>
    <p id="auth-error" style="font-size:12px;color:#f87171;margin:0;display:none">Invalid key</p>
  </div>

  <!-- ══ OVERVIEW PAGE ══ -->
  <div id="page-overview" class="tab-panel active">
    <p class="section-title">Fleet Overview</p>
    <p class="section-sub">Real-time stats across all beta testers</p>

    <!-- Top metrics -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px" id="overview-metrics">
      <div class="metric-card"><div class="metric-label">Online Now</div><div class="metric-val" id="ov-online">—</div><div class="metric-sub" id="ov-total"></div></div>
      <div class="metric-card"><div class="metric-label">Total Threats</div><div class="metric-val" style="color:#ef4444" id="ov-threats">—</div><div class="metric-sub">across fleet</div></div>
      <div class="metric-card"><div class="metric-label">Files Scanned</div><div class="metric-val" id="ov-scanned">—</div><div class="metric-sub">total</div></div>
      <div class="metric-card"><div class="metric-label">Quarantined</div><div class="metric-val" style="color:#f59e0b" id="ov-quar">—</div><div class="metric-sub">fleet total</div></div>
      <div class="metric-card"><div class="metric-label">Beta Keys</div><div class="metric-val" id="ov-keys">—</div><div class="metric-sub" id="ov-keys-sub"></div></div>
      <div class="metric-card"><div class="metric-label">Realtime On</div><div class="metric-val" style="color:#34d399" id="ov-rt">—</div><div class="metric-sub">clients</div></div>
    </div>

    <!-- Charts row -->
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-bottom:20px">
      <div class="card">
        <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 14px">Online vs Offline</p>
        <canvas id="chart-status" height="180"></canvas>
      </div>
      <div class="card">
        <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 14px">Platform Breakdown</p>
        <canvas id="chart-platform" height="180"></canvas>
      </div>
      <div class="card">
        <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 14px">Version Distribution</p>
        <canvas id="chart-version" height="180"></canvas>
      </div>
    </div>

    <!-- Avg resource gauges -->
    <div class="card" style="margin-bottom:20px">
      <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 14px">Fleet Average Resources</p>
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:20px" id="gauge-row">
        <div>
          <div style="display:flex;justify-content:space-between"><span style="font-size:11px;color:#71717a">CPU</span><span id="gauge-cpu-val" style="font-size:11px;color:#fff">—</span></div>
          <div class="gauge-bar"><div id="gauge-cpu" class="gauge-fill" style="background:#3b82f6;width:0%"></div></div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between"><span style="font-size:11px;color:#71717a">Memory</span><span id="gauge-mem-val" style="font-size:11px;color:#fff">—</span></div>
          <div class="gauge-bar"><div id="gauge-mem" class="gauge-fill" style="background:#8b5cf6;width:0%"></div></div>
        </div>
        <div>
          <div style="display:flex;justify-content:space-between"><span style="font-size:11px;color:#71717a">Disk</span><span id="gauge-disk-val" style="font-size:11px;color:#fff">—</span></div>
          <div class="gauge-bar"><div id="gauge-disk" class="gauge-fill" style="background:#f59e0b;width:0%"></div></div>
        </div>
      </div>
    </div>

    <!-- Recent clients mini list -->
    <div class="card">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
        <p style="font-size:12px;font-weight:600;color:#fff;margin:0">Recent Clients</p>
        <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px" onclick="showPage('clients')">View all →</button>
      </div>
      <div id="mini-clients"></div>
    </div>
  </div>

  <!-- ══ CLIENTS PAGE ══ -->
  <div id="page-clients" class="tab-panel">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:10px">
      <div><p class="section-title">Connected Clients</p><p class="section-sub" style="margin:0">All beta testers — live system data</p></div>
      <div style="display:flex;gap:8px;align-items:center">
        <input class="search-bar" id="client-search" placeholder="Search hostname, IP, key…" oninput="filterClients()">
        <select id="client-filter" style="width:130px" onchange="filterClients()">
          <option value="all">All clients</option>
          <option value="online">Online only</option>
          <option value="offline">Offline only</option>
        </select>
        <button class="btn btn-secondary" onclick="loadClients()">↻ Refresh</button>
      </div>
    </div>

    <div class="card" style="overflow:hidden;padding:0">
      <div class="table-header" style="grid-template-columns:18px 160px 100px 90px 90px 90px 80px 80px 80px 100px 1fr;display:grid">
        <span></span><span>Host</span><span>IP</span><span>CPU</span><span>RAM</span><span>Disk</span><span>Threats</span><span>Scanned</span><span>Uptime</span><span>Version</span><span>Last Seen</span>
      </div>
      <div id="clients-table"></div>
    </div>

    <!-- Expanded client detail panel -->
    <div id="client-detail" style="display:none;margin-top:14px" class="card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <p style="font-size:14px;font-weight:700;color:#fff;margin:0" id="detail-title">Client Details</p>
        <button class="btn btn-secondary" style="font-size:11px;padding:4px 10px" onclick="closeDetail()">✕ Close</button>
      </div>
      <div id="detail-body" style="display:grid;grid-template-columns:1fr 1fr;gap:16px"></div>
    </div>
  </div>

  <!-- ══ KEYS PAGE ══ -->
  <div id="page-keys" class="tab-panel">
    <p class="section-title">Beta Keys</p>
    <p class="section-sub">Generate and manage access keys for testers</p>

    <div class="card" style="margin-bottom:16px">
      <p style="font-size:13px;font-weight:600;color:#fff;margin:0 0 12px">Generate New Key</p>
      <div style="display:grid;grid-template-columns:1fr 160px 140px auto;gap:8px;align-items:end">
        <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Tester / Label</label><input id="key-label" placeholder="e.g. John Doe"></div>
        <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Max Devices</label><input id="key-max" type="number" value="1" min="1" max="20"></div>
        <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Note</label><input id="key-note" placeholder="Optional note"></div>
        <button class="btn btn-primary" onclick="generateKey()">+ Generate</button>
      </div>
      <div id="new-key-result" style="display:none;margin-top:12px;padding:12px 16px;background:#0e0e12;border:1px solid #27272a;border-radius:10px;display:flex;align-items:center;gap:12px">
        <span id="new-key-text" style="font-family:monospace;font-size:16px;font-weight:700;color:#34d399;letter-spacing:.08em;flex:1"></span>
        <button class="btn btn-green" onclick="copyNewKey()">Copy</button>
      </div>
    </div>

    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
      <input class="search-bar" id="key-search" placeholder="Search keys…" oninput="filterKeys()" style="width:220px">
      <select id="key-filter" style="width:130px" onchange="filterKeys()">
        <option value="all">All keys</option>
        <option value="active">Active only</option>
        <option value="revoked">Revoked only</option>
      </select>
    </div>
    <div class="card" style="overflow:hidden;padding:0">
      <div class="table-header" style="grid-template-columns:220px 1fr 100px 80px 100px 160px;display:grid">
        <span>Key</span><span>Label</span><span>Uses</span><span>Status</span><span>Created</span><span>Actions</span>
      </div>
      <div id="keys-table"></div>
    </div>
  </div>

  <!-- ══ UPDATES PAGE ══ -->
  <div id="page-updates" class="tab-panel">
    <p class="section-title">Update Management</p>
    <p class="section-sub">Push new versions and release notes to all beta testers</p>

    <div style="display:grid;grid-template-columns:1fr 380px;gap:16px;align-items:start">
      <div class="card">
        <p style="font-size:13px;font-weight:600;color:#fff;margin:0 0 14px">Publish New Version</p>
        <div style="display:grid;gap:12px">
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
            <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Version</label><input id="upd-version" placeholder="1.0.1"></div>
            <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Download URL</label><input id="upd-url" placeholder="https://…"></div>
          </div>
          <div><label style="font-size:10px;color:#71717a;display:block;margin-bottom:4px;text-transform:uppercase;letter-spacing:.06em">Release Notes (shown to users)</label><textarea id="upd-notes" rows="5" placeholder="What's new…"></textarea></div>
          <div style="display:flex;align-items:center;gap:8px">
            <input type="checkbox" id="upd-required" style="width:auto;accent-color:#ef4444">
            <label style="font-size:12px;color:#a1a1aa;cursor:pointer" for="upd-required">Force update — users cannot dismiss</label>
          </div>
          <div style="display:flex;gap:8px">
            <button class="btn btn-primary" onclick="publishUpdate()">🚀 Publish Update</button>
            <button class="btn btn-danger" onclick="clearUpdate()" id="clear-update-btn" style="display:none">Clear Published</button>
          </div>
          <p id="update-status-msg" style="font-size:12px;margin:0;display:none"></p>
        </div>
      </div>

      <div>
        <div class="card" style="margin-bottom:12px" id="current-update-card">
          <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 12px">Currently Published</p>
          <div id="current-update"></div>
        </div>
        <div class="card">
          <p style="font-size:12px;font-weight:600;color:#fff;margin:0 0 10px">Client Version Coverage</p>
          <canvas id="chart-version-updates" height="160"></canvas>
        </div>
      </div>
    </div>
  </div>

</main>

<script>
let _adminKey = localStorage.getItem('sentinel_admin_key') || '';
const BASE = window.location.origin;
let _allClients = [];
let _allKeys = {};
let _charts = {};
let _newKey = '';

Chart.defaults.color = '#71717a';
Chart.defaults.borderColor = '#1c1c21';

function _chartColors(n) {
  const palette = ['#3b82f6','#8b5cf6','#34d399','#f59e0b','#ef4444','#ec4899','#06b6d4','#84cc16'];
  return Array.from({length:n}, (_,i) => palette[i % palette.length]);
}

function makeDoughnut(id, labels, values) {
  const ctx = document.getElementById(id);
  if (!ctx) return;
  if (_charts[id]) _charts[id].destroy();
  _charts[id] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: values, backgroundColor: _chartColors(values.length), borderWidth: 0, hoverOffset: 4 }]
    },
    options: {
      cutout: '68%',
      plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, font: { size: 11 }, padding: 10 } } },
      animation: { duration: 500 }
    }
  });
}

async function apiFetch(path, opts = {}) {
  const res = await fetch(BASE + path, {
    ...opts,
    headers: { 'X-Admin-Key': _adminKey, 'Content-Type': 'application/json', ...(opts.headers||{}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 403) {
    document.getElementById('auth-error').style.display = 'inline';
    throw new Error('403');
  }
  document.getElementById('auth-error').style.display = 'none';
  return res.json();
}

function setAdminKey() {
  _adminKey = document.getElementById('admin-key-input').value.trim();
  localStorage.setItem('sentinel_admin_key', _adminKey);
  document.getElementById('auth-bar').style.display = 'none';
  document.getElementById('auth-status').textContent = 'Authenticated';
  document.getElementById('auth-status').style.color = '#34d399';
  loadAll();
}

function showPage(name) {
  document.querySelectorAll('.tab-panel').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');
  if (name === 'overview') loadOverview();
  if (name === 'clients') loadClients();
  if (name === 'keys') loadKeys();
  if (name === 'updates') { loadCurrentUpdate(); loadVersionChart(); }
}

// ── OVERVIEW ──────────────────────────────────────────────────────────────────
async function loadOverview() {
  try {
    const s = await apiFetch('/admin/stats');
    document.getElementById('ov-online').textContent = s.online;
    document.getElementById('ov-total').textContent = `of ${s.total_clients} total`;
    document.getElementById('ov-threats').textContent = s.total_threats.toLocaleString();
    document.getElementById('ov-scanned').textContent = s.total_scanned.toLocaleString();
    document.getElementById('ov-quar').textContent = s.total_quarantine.toLocaleString();
    document.getElementById('ov-keys').textContent = s.active_keys;
    document.getElementById('ov-keys-sub').textContent = `${s.total_activations} activations`;
    document.getElementById('ov-rt').textContent = s.realtime_active;

    document.getElementById('online-pill').textContent = s.online;
    document.getElementById('online-pill').style.display = s.online > 0 ? 'inline' : 'none';

    makeDoughnut('chart-status', ['Online','Offline'], [s.online, s.offline]);
    makeDoughnut('chart-platform', Object.keys(s.platforms), Object.values(s.platforms));
    makeDoughnut('chart-version', Object.keys(s.versions), Object.values(s.versions));

    const setGauge = (id, val) => {
      document.getElementById('gauge-' + id).style.width = val + '%';
      document.getElementById('gauge-' + id + '-val').textContent = val.toFixed(1) + '%';
      const fill = document.getElementById('gauge-' + id);
      fill.style.background = val > 85 ? '#ef4444' : val > 60 ? '#f59e0b' : (id==='cpu'?'#3b82f6':id==='mem'?'#8b5cf6':'#f59e0b');
    };
    setGauge('cpu', s.avg_cpu); setGauge('mem', s.avg_mem); setGauge('disk', s.avg_disk);

    const clients = await apiFetch('/admin/clients');
    _allClients = clients;
    const mini = document.getElementById('mini-clients');
    if (clients.length === 0) { mini.innerHTML='<p style="font-size:12px;color:#71717a;padding:8px">No clients yet.</p>'; return; }
    mini.innerHTML = clients.slice(0,5).map(c => `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid #1c1c21">
        <span class="${c.online?'badge-on':'badge-off'}">${c.online?'●':'○'}</span>
        <span style="font-size:13px;font-weight:600;color:#fff;flex:1">${c.hostname||'—'}</span>
        <span style="font-size:11px;color:#71717a">${c.ip||''}</span>
        <span style="font-size:11px;color:#52525b">${fmtAgo(c.last_seen)}</span>
        <span style="font-size:11px;padding:1px 6px;border-radius:4px;background:#1c1c21;border:1px solid #27272a;color:#a1a1aa">${c.threats_found??0} threats</span>
      </div>`).join('');
  } catch(e) { if(e.message!=='403') console.error(e); }
}

// ── CLIENTS ───────────────────────────────────────────────────────────────────
function fmtUptime(s) {
  if (!s) return '—';
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60);
  return h > 0 ? `${h}h ${m}m` : `${m}m`;
}
function fmtAgo(iso) {
  if (!iso) return '—';
  const d = (Date.now() - new Date(iso).getTime()) / 1000;
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d/60)}m ago`;
  if (d < 86400) return `${Math.floor(d/3600)}h ago`;
  return `${Math.floor(d/86400)}d ago`;
}
function pct(v) { return v != null ? v.toFixed(1)+'%' : '—'; }

async function loadClients() {
  try {
    _allClients = await apiFetch('/admin/clients');
    renderClientTable(_allClients);
  } catch(e) {}
}

function filterClients() {
  const q = document.getElementById('client-search').value.toLowerCase();
  const f = document.getElementById('client-filter').value;
  let list = _allClients.filter(c => {
    const match = !q || [c.hostname,c.ip,c.beta_key,c.platform].join(' ').toLowerCase().includes(q);
    const status = f==='all' || (f==='online' && c.online) || (f==='offline' && !c.online);
    return match && status;
  });
  renderClientTable(list);
}

function renderClientTable(data) {
  const cols = 'grid-template-columns:18px 160px 100px 90px 90px 90px 80px 80px 80px 100px 1fr';
  const tbody = document.getElementById('clients-table');
  if (data.length === 0) { tbody.innerHTML='<p style="padding:16px;color:#71717a;font-size:12px">No clients match.</p>'; return; }
  tbody.innerHTML = data.map((c,i) => `
    <div class="table-row" style="${cols}" onclick="expandClient(${i})" data-idx="${i}" style="cursor:pointer">
      <span style="width:8px;height:8px;border-radius:9999px;background:${c.online?'#34d399':'#27272a'};display:inline-block"></span>
      <span style="font-weight:600;color:#fff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${c.hostname||'—'}</span>
      <span style="color:#71717a">${c.ip||'—'}</span>
      <span style="color:${(c.cpu_percent||0)>80?'#ef4444':'#e4e4e7'}">${pct(c.cpu_percent)}</span>
      <span style="color:${(c.memory_percent||0)>80?'#ef4444':'#e4e4e7'}">${pct(c.memory_percent)}</span>
      <span style="color:${(c.disk_percent||0)>90?'#ef4444':'#e4e4e7'}">${pct(c.disk_percent)}</span>
      <span style="color:${c.threats_found>0?'#f87171':'#e4e4e7'}">${c.threats_found??0}</span>
      <span>${(c.files_scanned||0).toLocaleString()}</span>
      <span style="color:#71717a">${fmtUptime(c.uptime_seconds)}</span>
      <span style="color:#a1a1aa;font-family:monospace;font-size:11px">${c.version||'—'}</span>
      <span style="color:#52525b">${fmtAgo(c.last_seen)}</span>
    </div>`).join('');
}

let _expandedIdx = null;
function expandClient(i) {
  const c = _allClients[i];
  if (!c) return;
  if (_expandedIdx === i) { closeDetail(); return; }
  _expandedIdx = i;
  document.getElementById('client-detail').style.display = 'block';
  document.getElementById('detail-title').textContent = c.hostname || 'Client Detail';
  document.getElementById('detail-body').innerHTML = `
    <div style="display:grid;gap:8px">
      ${dRow('Status', c.online ? '<span class="badge-on">● Online</span>' : '<span class="badge-off">○ Offline</span>')}
      ${dRow('IP Address', c.ip||'—')}
      ${dRow('Platform', c.platform||'—')}
      ${dRow('Version', c.version||'—')}
      ${dRow('Beta Key', `<span style="font-family:monospace;font-size:11px;color:#a1a1aa">${c.beta_key||'—'}</span>`)}
      ${dRow('Machine ID', `<span style="font-family:monospace;font-size:11px;color:#52525b">${c.machine_id||'—'}</span>`)}
      ${dRow('First Seen', c.first_seen ? new Date(c.first_seen).toLocaleString() : '—')}
      ${dRow('Last Seen', c.last_seen ? new Date(c.last_seen).toLocaleString() : '—')}
    </div>
    <div style="display:grid;gap:8px">
      ${dRow('CPU', pct(c.cpu_percent))}
      ${dRow('Memory', pct(c.memory_percent))}
      ${dRow('Disk', pct(c.disk_percent))}
      ${dRow('Uptime', fmtUptime(c.uptime_seconds))}
      ${dRow('Threats Found', `<span style="color:${c.threats_found>0?'#f87171':'#34d399'};font-weight:700">${c.threats_found??0}</span>`)}
      ${dRow('Files Scanned', (c.files_scanned||0).toLocaleString())}
      ${dRow('Quarantined', c.quarantine_count??0)}
      ${dRow('Realtime Active', c.realtime_active ? '<span class="badge-on">On</span>' : '<span class="badge-off">Off</span>')}
    </div>`;
}
function dRow(label, val) {
  return `<div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #1c1c21"><span style="font-size:11px;color:#71717a">${label}</span><span style="font-size:12px;color:#e4e4e7">${val}</span></div>`;
}
function closeDetail() { document.getElementById('client-detail').style.display='none'; _expandedIdx=null; }

// ── KEYS ──────────────────────────────────────────────────────────────────────
async function loadKeys() {
  try {
    _allKeys = await apiFetch('/admin/keys');
    renderKeysTable(_allKeys);
  } catch(e) {}
}

function filterKeys() {
  const q = document.getElementById('key-search').value.toLowerCase();
  const f = document.getElementById('key-filter').value;
  const filtered = {};
  Object.entries(_allKeys).forEach(([k,v]) => {
    const match = !q || k.toLowerCase().includes(q) || (v.label||'').toLowerCase().includes(q);
    const status = f==='all' || (f==='active'&&v.active) || (f==='revoked'&&!v.active);
    if (match && status) filtered[k] = v;
  });
  renderKeysTable(filtered);
}

function renderKeysTable(data) {
  const cols = 'grid-template-columns:220px 1fr 100px 80px 100px 160px';
  const tbody = document.getElementById('keys-table');
  const keys = Object.entries(data);
  if (keys.length===0) { tbody.innerHTML='<p style="padding:16px;color:#71717a;font-size:12px">No keys found.</p>'; return; }
  tbody.innerHTML = keys.map(([k,v]) => `
    <div class="table-row" style="${cols}">
      <span style="font-family:monospace;font-size:12px;font-weight:700;color:${v.active?'#34d399':'#52525b'}">${k}</span>
      <span style="color:#a1a1aa;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${v.label||'—'}</span>
      <span>
        <div style="display:flex;align-items:center;gap:4px">
          <div style="flex:1;height:4px;border-radius:9999px;background:#1c1c21;overflow:hidden">
            <div style="height:100%;border-radius:9999px;background:#3b82f6;width:${Math.round((v.uses/Math.max(v.max_uses,1))*100)}%"></div>
          </div>
          <span style="font-size:10px;color:#71717a;white-space:nowrap">${v.uses}/${v.max_uses}</span>
        </div>
      </span>
      <span><span style="font-size:10px;padding:2px 7px;border-radius:9999px;background:${v.active?'rgba(16,185,129,.15)':'rgba(113,113,122,.12)'};color:${v.active?'#34d399':'#52525b'};border:1px solid ${v.active?'rgba(16,185,129,.3)':'rgba(113,113,122,.2)'}">${v.active?'Active':'Revoked'}</span></span>
      <span style="color:#52525b;font-size:11px">${v.created?new Date(v.created).toLocaleDateString():'—'}</span>
      <span style="display:flex;gap:5px">
        <button class="btn btn-secondary" style="font-size:10px;padding:3px 8px" onclick="copyKey('${k}')">Copy</button>
        ${v.active?`<button class="btn btn-danger" style="font-size:10px;padding:3px 8px" onclick="revokeKey('${k}')">Revoke</button>`:''}
        <button class="btn btn-danger" style="font-size:10px;padding:3px 8px" onclick="deleteKey('${k}')">Del</button>
      </span>
    </div>`).join('');
}

async function generateKey() {
  const label = document.getElementById('key-label').value.trim();
  const max_uses = parseInt(document.getElementById('key-max').value)||1;
  const data = await apiFetch('/admin/keys/generate', {method:'POST', body:{label,max_uses}});
  if (data.success) {
    _newKey = data.key;
    document.getElementById('new-key-text').textContent = data.key;
    document.getElementById('new-key-result').style.display = 'flex';
    document.getElementById('key-label').value = '';
    await loadKeys();
  }
}
function copyNewKey() { navigator.clipboard.writeText(_newKey); }
function copyKey(k) { navigator.clipboard.writeText(k); }
async function revokeKey(k) {
  if (!confirm('Revoke key ' + k + '?')) return;
  await apiFetch(`/admin/keys/${encodeURIComponent(k)}/revoke`, {method:'POST'});
  loadKeys();
}
async function deleteKey(k) {
  if (!confirm('Permanently delete key ' + k + '?')) return;
  await apiFetch(`/admin/keys/${encodeURIComponent(k)}/delete`, {method:'POST'});
  loadKeys();
}

// ── UPDATES ───────────────────────────────────────────────────────────────────
async function loadCurrentUpdate() {
  try {
    const d = await apiFetch('/admin/updates');
    const el = document.getElementById('current-update');
    const clearBtn = document.getElementById('clear-update-btn');
    if (!d.latest_version) {
      el.innerHTML = '<p style="font-size:12px;color:#71717a">No update published.</p>';
      if (clearBtn) clearBtn.style.display = 'none';
      return;
    }
    if (clearBtn) clearBtn.style.display = 'inline-flex';
    el.innerHTML = `
      <div style="display:grid;gap:6px;font-size:12px">
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:18px;font-weight:800;color:#fff">v${d.latest_version}</span>
          ${d.required?'<span style="font-size:10px;background:#ef4444;color:#fff;padding:2px 8px;border-radius:9999px;font-weight:700">REQUIRED</span>':''}
        </div>
        ${d.download_url?`<a href="${d.download_url}" target="_blank" style="color:#3b82f6;font-size:11px;word-break:break-all">${d.download_url}</a>`:''}
        <p style="color:#a1a1aa;font-size:11px;margin:4px 0;white-space:pre-wrap">${d.release_notes||'—'}</p>
        <p style="color:#52525b;font-size:10px">Published ${d.published_at?new Date(d.published_at).toLocaleString():'—'}</p>
      </div>`;
  } catch(e) {}
}

async function loadVersionChart() {
  try {
    const s = await apiFetch('/admin/stats');
    makeDoughnut('chart-version-updates', Object.keys(s.versions), Object.values(s.versions));
  } catch(e) {}
}

async function publishUpdate() {
  const version = document.getElementById('upd-version').value.trim();
  const download_url = document.getElementById('upd-url').value.trim();
  const release_notes = document.getElementById('upd-notes').value.trim();
  const required = document.getElementById('upd-required').checked;
  const msg = document.getElementById('update-status-msg');
  if (!version) { msg.style.display='block'; msg.style.color='#f87171'; msg.textContent='Version is required.'; return; }
  const data = await apiFetch('/admin/updates/publish', {method:'POST', body:{version,download_url,release_notes,required}});
  if (data.success) {
    msg.style.display='block'; msg.style.color='#34d399'; msg.textContent='Update published! Clients will be notified on next heartbeat.';
    loadCurrentUpdate(); loadVersionChart();
  }
}

async function clearUpdate() {
  if (!confirm('Clear the published update?')) return;
  await apiFetch('/admin/updates/publish', {method:'POST', body:{version:'',download_url:'',release_notes:'',required:false}});
  loadCurrentUpdate();
}

// ── INIT ──────────────────────────────────────────────────────────────────────
function loadAll() { loadOverview(); }

if (_adminKey) {
  document.getElementById('auth-bar').style.display = 'none';
  document.getElementById('auth-status').textContent = 'Authenticated';
  document.getElementById('auth-status').style.color = '#34d399';
  loadAll();
  setInterval(loadOverview, 30000);
  setInterval(() => { if (document.getElementById('page-clients').classList.contains('active')) loadClients(); }, 15000);
}
lucide.createIcons();
</script>
</body>
</html>"""


@app.route("/api/beta/feedback", methods=["POST"])
def beta_submit_feedback():
    """Public endpoint — authenticated testers submit feedback/diagnostics."""
    data = request.get_json(silent=True) or {}
    beta_key = data.get("beta_key", "").strip()
    # Validate key exists
    keys = _load(_KEYS_FILE, {})
    valid = any(k.get("key") == beta_key and k.get("active") for k in keys.values()) if keys else True
    if not valid:
        return jsonify({"success": False, "error": "Invalid beta key"}), 403

    feedback_list = _load(_FEEDBACK_FILE, [])
    entry = {
        "id": secrets.token_hex(6),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "machine_id": data.get("machine_id", "unknown"),
        "beta_key": beta_key,
        "label": data.get("label", "General"),
        "type": data.get("type", "suggestion"),  # suggestion | bug | diagnostic
        "message": str(data.get("message", ""))[:4000],
        "diagnostics": data.get("diagnostics", {}),
        "read": False,
    }
    feedback_list.insert(0, entry)
    with open(_FEEDBACK_FILE, "w") as f:
        json.dump(feedback_list[:500], f, indent=2)
    return jsonify({"success": True})


@app.route("/admin/feedback", methods=["GET"])
def admin_get_feedback():
    _require_admin()
    return jsonify(_load(_FEEDBACK_FILE, []))


@app.route("/admin/feedback/<fid>/read", methods=["POST"])
def admin_mark_feedback_read(fid):
    _require_admin()
    items = _load(_FEEDBACK_FILE, [])
    for item in items:
        if item.get("id") == fid:
            item["read"] = True
            break
    with open(_FEEDBACK_FILE, "w") as f:
        json.dump(items, f, indent=2)
    return jsonify({"success": True})


@app.route("/admin/feedback/<fid>", methods=["DELETE"])
def admin_delete_feedback(fid):
    _require_admin()
    items = _load(_FEEDBACK_FILE, [])
    items = [i for i in items if i.get("id") != fid]
    with open(_FEEDBACK_FILE, "w") as f:
        json.dump(items, f, indent=2)
    return jsonify({"success": True})


@app.route("/admin")
def admin_ui():
    return _load_panel()

@app.route("/setup")
def setup_page():
    return _load_panel()


@app.route("/")
def index():
    from flask import redirect
    return redirect("/admin")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18082)
    args = parser.parse_args()
    print(f"Sentinel Admin Server starting on port {args.port}")
    print(f"Admin UI: http://127.0.0.1:{args.port}/admin")
    app.run(host="0.0.0.0", port=args.port, debug=False)
