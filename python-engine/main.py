"""Standalone Python security engine for the Electron security suite."""

import argparse
import json
import os
import platform
import socket
import subprocess
import sys
import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, wait as futures_wait, FIRST_COMPLETED
from datetime import datetime
from pathlib import Path

import psutil
import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from license_client import LicenseClient
from security import SecurityScanner, get_local_subnet
from threat_engine import FileScanner, RealTimeMonitor

app = Flask(__name__)
CORS(app)

# When bundled with PyInstaller, data lives next to the executable.
if getattr(sys, 'frozen', False):
    base_dir = os.path.dirname(sys.executable)
    # On macOS/Windows packaged app, write data to user's writable app support dir
    if sys.platform == 'darwin':
        _app_support = os.path.expanduser('~/Library/Application Support/sentinel-security-suite')
    elif sys.platform == 'win32':
        _app_support = os.path.join(os.environ.get('APPDATA', os.path.expanduser('~')), 'sentinel-security-suite')
    else:
        _app_support = os.path.expanduser('~/.sentinel-security-suite')
    data_dir = _app_support
else:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(base_dir, "data")

os.makedirs(data_dir, exist_ok=True)
scanner = SecurityScanner(data_dir=data_dir)

_quarantine_dir = os.path.join(data_dir, "quarantine")
_writable_base = data_dir if getattr(sys, 'frozen', False) else base_dir
file_scanner = FileScanner(quarantine_dir=_quarantine_dir, base_dir=_writable_base)
license_client = LicenseClient(base_dir=_writable_base)
realtime_monitor = None

# Active scan sessions keyed by scan_id
scan_sessions = {}
_scan_session_lock = threading.Lock()

# Feed update state
last_feed_update = None
feed_update_interval = 3600  # 1 hour
feed_update_running = False

# ── Beta / Admin config ────────────────────────────────────────────────────────
_APP_VERSION = "1.0.0-beta"
_ADMIN_SERVER_URL = ""          # set via /api/admin/configure or config file
_BETA_KEY = ""                  # set by user on first launch
_MACHINE_ID = ""                # stable per-machine UUID
_pending_update = {}            # populated by heartbeat response

_beta_config_file = os.path.join(data_dir, "beta_config.json")

def _get_stable_machine_id():
    """Return a stable per-machine UUID that works on Windows, macOS, and Linux."""
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r"SOFTWARE\Microsoft\Cryptography")
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            return val
        except Exception:
            pass
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        if os.path.exists(path):
            try:
                return open(path).read().strip()
            except Exception:
                pass
    return str(uuid.uuid4())

def _load_beta_config():
    global _ADMIN_SERVER_URL, _BETA_KEY, _MACHINE_ID
    if os.path.exists(_beta_config_file):
        try:
            cfg = json.load(open(_beta_config_file))
            _ADMIN_SERVER_URL = cfg.get("admin_url", "")
            _BETA_KEY = cfg.get("beta_key", "")
            _MACHINE_ID = cfg.get("machine_id", "")
        except Exception:
            pass
    if not _MACHINE_ID:
        _MACHINE_ID = _get_stable_machine_id()
        _save_beta_config()

def _save_beta_config():
    with open(_beta_config_file, "w") as f:
        json.dump({"admin_url": _ADMIN_SERVER_URL, "beta_key": _BETA_KEY, "machine_id": _MACHINE_ID}, f)

_load_beta_config()


def _build_heartbeat_payload():
    """Build the telemetry payload to send to the admin server."""
    cpu = psutil.cpu_percent(interval=None)
    mem = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage("C:\\" if sys.platform == "win32" else "/")
        disk_pct = disk.percent
    except Exception:
        disk_pct = 0.0
    boot = psutil.boot_time()
    return {
        "machine_id": _MACHINE_ID,
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "beta_key": _BETA_KEY,
        "version": _APP_VERSION,
        "cpu_percent": cpu,
        "memory_percent": mem.percent,
        "disk_percent": disk_pct,
        "threats_found": len(file_scanner.results),
        "files_scanned": sum(s.get("files_scanned", 0) for s in scan_sessions.values()),
        "quarantine_count": len(file_scanner.get_quarantined_files()),
        "realtime_active": realtime_monitor.is_running() if realtime_monitor else False,
        "uptime_seconds": int(time.time() - boot),
    }

def _send_heartbeat():
    """Send one heartbeat. Returns True on success."""
    global _pending_update
    if not _ADMIN_SERVER_URL or not _BETA_KEY:
        return False
    try:
        payload = _build_heartbeat_payload()
        resp = requests.post(
            f"{_ADMIN_SERVER_URL.rstrip('/')}/api/client/heartbeat",
            json=payload, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("latest_version") and data["latest_version"] != _APP_VERSION:
                _pending_update = data
            return True
    except Exception:
        pass
    return False

def _heartbeat_worker():
    """Send system telemetry to admin server every 60s. Retries with backoff on failure."""
    # Send first heartbeat shortly after startup
    time.sleep(5)
    _send_heartbeat()

    fail_count = 0
    while True:
        # Normal interval is 60s; back off up to 10 min on repeated failures
        interval = min(60 * (2 ** fail_count), 600)
        time.sleep(interval)
        success = _send_heartbeat()
        if success:
            fail_count = 0          # reset backoff on success
        else:
            fail_count = min(fail_count + 1, 4)  # cap at ~10 min backoff

def _on_realtime_threat(result):
    scanner.add_alert("malware", f"Real-time detection: {result['description']} in {result['path']}", result)


def get_size(bytes_value):
    """Convert bytes to human-readable format."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def ping_host(host, timeout=1):
    """Return True if host responds to ping, else False."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), str(host)]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), str(host)]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def get_public_ip():
    try:
        import requests as _req
        return _req.get("https://api.ipify.org", timeout=5).text.strip()
    except Exception:
        return "Unknown"


@app.route("/api/status")
def api_status():
    return jsonify({"status": "ok", "engine": "security-suite-python"})


@app.route("/api/system")
def api_system():
    cpu = psutil.cpu_percent(interval=None)  # non-blocking; uses last sample
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    boot_time = psutil.boot_time()
    uptime = time.time() - boot_time

    return jsonify({
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "username": os.environ.get("USER") or os.environ.get("USERNAME") or "",
        "home_dir": str(Path.home()),
        "cpu_percent": cpu,
        "cpu_count": psutil.cpu_count(),
        "memory": {
            "total": get_size(memory.total),
            "used": get_size(memory.used),
            "percent": memory.percent,
        },
        "disk": {
            "total": get_size(disk.total),
            "used": get_size(disk.used),
            "percent": 100 * disk.used / disk.total,
        },
        "uptime_seconds": int(uptime),
    })


_cached_network = {"result": None, "ts": 0.0}
_NETWORK_CACHE_TTL = 30  # seconds


@app.route("/api/network")
def api_network():
    now = time.time()
    if _cached_network["result"] and now - _cached_network["ts"] < _NETWORK_CACHE_TTL:
        return jsonify(_cached_network["result"])

    def get_local_ip():
        for iface in psutil.net_if_addrs().values():
            for addr in iface:
                if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                    return addr.address
        return "127.0.0.1"

    with ThreadPoolExecutor(max_workers=3) as executor:
        google_future = executor.submit(ping_host, "8.8.8.8")
        cloudflare_future = executor.submit(ping_host, "1.1.1.1")
        public_ip_future = executor.submit(get_public_ip)

    result = {
        "public_ip": public_ip_future.result(),
        "local_ip": get_local_ip(),
        "ping_google": 0.0 if google_future.result() else None,
        "ping_cloudflare": 0.0 if cloudflare_future.result() else None,
    }
    _cached_network["result"] = result
    _cached_network["ts"] = time.time()
    return jsonify(result)


@app.route("/api/processes")
def api_processes():
    procs = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
        try:
            procs.append(proc.info)
        except Exception:
            pass
    procs.sort(key=lambda p: p.get("cpu_percent") or 0, reverse=True)
    return jsonify({"processes": procs[:15]})


@app.route("/api/security/subnet")
def api_security_subnet():
    return jsonify({"subnet": get_local_subnet()})


@app.route("/api/security/scan", methods=["POST"])
def api_security_scan():
    license_error = _require_license()
    if license_error:
        return license_error
    data = request.json or {}
    subnet = data.get("subnet") or get_local_subnet()
    full_scan = data.get("full_scan", False)
    try:
        devices = scanner.scan(subnet=subnet, full_scan=full_scan)
        return jsonify({"success": True, "devices": devices, "count": len(devices)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/security/devices")
def api_security_devices():
    latest = scanner.load_baseline()
    if latest is None:
        latest = scanner.save_latest_scan([])
    return jsonify(latest)


@app.route("/api/security/baseline", methods=["POST"])
def api_security_baseline():
    latest = {"devices": []}
    if os.path.exists(scanner.scan_file):
        with open(scanner.scan_file, "r", encoding="utf-8") as f:
            latest = json.load(f)
    baseline = scanner.save_baseline(latest.get("devices", []))
    return jsonify({"success": True, "baseline": baseline})


@app.route("/api/security/alerts")
def api_security_alerts():
    return jsonify(scanner.load_alerts())


@app.route("/api/security/alerts/<int:alert_id>/read", methods=["POST"])
def api_security_alert_read(alert_id):
    return jsonify(scanner.mark_alert_read(alert_id))


_THREAT_SEVERITY_MAP = {
    "virus": "critical", "known_malware": "critical", "virustotal": "critical",
    "malwarebazaar": "critical", "threatfox": "critical",
    "yara": "high", "embedded_executable": "high", "suspicious_script": "high",
    "suspicious_name": "high", "suspicious_extension": "high",
    "high_entropy": "medium", "suspicious_content": "medium",
}

_THREAT_LABEL_MAP = {
    "virus": "Virus Detected", "known_malware": "Known Malware Hash",
    "virustotal": "VirusTotal Match", "malwarebazaar": "MalwareBazaar Match",
    "threatfox": "ThreatFox IOC", "yara": "YARA Rule Match",
    "high_entropy": "High Entropy Content", "embedded_executable": "Embedded Executable",
    "suspicious_script": "Suspicious Script", "suspicious_content": "Suspicious Content",
    "suspicious_extension": "Double Extension", "suspicious_name": "Suspicious Name",
}

_THREAT_RISK_MAP = {
    "virus": "Can infect other files, spread through the system, or exfiltrate data",
    "known_malware": "Confirmed malicious binary — do not execute",
    "virustotal": "May steal data, damage files, or provide remote access to attackers",
    "malwarebazaar": "Confirmed malicious — treat as active threat",
    "threatfox": "Associated with active threat campaigns or C2 infrastructure",
    "yara": "Exhibits characteristics of known malware families",
    "high_entropy": "Packed or encrypted payloads are commonly used to hide malware from scanners",
    "embedded_executable": "Attackers embed executables inside documents or images to bypass security filters",
    "suspicious_script": "Can execute system commands, download payloads, or modify registry/startup items",
    "suspicious_content": "May attempt to execute hidden commands or obfuscated payloads",
    "suspicious_extension": "Trick users into running malware thinking it is a safe document",
    "suspicious_name": "Crack/keygen/patch tools frequently bundle trojans or adware",
}


@app.route("/api/alerts")
def api_all_alerts():
    """Unified alerts: threat scanner events + network security alerts."""
    all_alerts = []

    # Threat scanner results → alerts
    for r in file_scanner.results:
        d = r.to_dict()
        threat_type = d.get("threat_type", "")
        sev = d.get("severity") or _THREAT_SEVERITY_MAP.get(threat_type, "medium")
        label = _THREAT_LABEL_MAP.get(threat_type, threat_type.replace("_", " ").title())
        risk = _THREAT_RISK_MAP.get(threat_type, "Unknown behaviour")
        all_alerts.append({
            "id": f"threat_{hash(d.get('path','') + d.get('timestamp',''))}",
            "source": "scanner",
            "type": threat_type,
            "label": label,
            "message": d.get("description", label),
            "risk": risk,
            "severity": sev,
            "path": getattr(r, "original_path", d.get("path", "")),
            "file_hash": d.get("file_hash", ""),
            "file_size": d.get("file_size", 0),
            "auto_quarantined": getattr(r, "quarantined", False),
            "timestamp": d.get("timestamp", ""),
            "read": False,
        })

    # Quarantine entries → alerts (for files quarantined in previous sessions)
    quarantined_paths = {getattr(r, "original_path", None) for r in file_scanner.results}
    for q in file_scanner.get_quarantined_files():
        orig = q.get("original_path")
        if orig and orig in quarantined_paths:
            continue  # already covered above
        threat_type = q.get("threat_type") or "unknown"
        sev = q.get("severity") or _THREAT_SEVERITY_MAP.get(threat_type, "medium")
        label = _THREAT_LABEL_MAP.get(threat_type, threat_type.replace("_", " ").title())
        risk = _THREAT_RISK_MAP.get(threat_type, "Unknown behaviour")
        all_alerts.append({
            "id": f"quar_{hash(q.get('path',''))}",
            "source": "quarantine",
            "type": threat_type,
            "label": label,
            "message": q.get("description") or f"Quarantined: {label}",
            "risk": risk,
            "severity": sev,
            "path": orig or q.get("path", ""),
            "file_hash": q.get("file_hash", ""),
            "file_size": q.get("size", 0),
            "auto_quarantined": True,
            "timestamp": q.get("timestamp", ""),
            "read": False,
        })

    # Network security alerts
    for a in scanner.load_alerts():
        sev = "low"
        if "new device" in a.get("message", "").lower():
            sev = "medium"
        if "threat" in a.get("message", "").lower():
            sev = "high"
        all_alerts.append({
            "id": f"net_{a.get('id', '')}",
            "source": "network",
            "type": a.get("type", "network"),
            "label": "Network Alert",
            "message": a.get("message", ""),
            "risk": "Unexpected network activity — may indicate intrusion or rogue device",
            "severity": sev,
            "path": "",
            "file_hash": "",
            "file_size": 0,
            "auto_quarantined": False,
            "timestamp": a.get("timestamp", ""),
            "read": a.get("read", False),
        })

    # Sort newest first
    all_alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(all_alerts)


@app.route("/api/alerts/history")
def api_alerts_history():
    """Return all archived alerts from previous sessions."""
    history_file = os.path.join(data_dir, "alert_history.json")
    try:
        with open(history_file, encoding="utf-8") as f:
            return jsonify(json.load(f))
    except Exception:
        return jsonify([])


@app.route("/api/security/alerts/clear", methods=["POST"])
def api_clear_alerts():
    """Clear all alerts: threat scanner results and network security alerts."""
    file_scanner.results.clear()
    # Clear network/security alerts file
    alerts_file = scanner.alerts_file
    try:
        import json as _json
        with open(alerts_file, "w", encoding="utf-8") as f:
            _json.dump([], f)
    except Exception:
        pass
    return jsonify({"success": True})


# === THREATS / MALWARE SCANNING ===

@app.route("/api/threats/status")
def api_threats_status():
    global realtime_monitor
    return jsonify({
        "clamav_available": file_scanner.clamav_available,
        "realtime_active": realtime_monitor.is_running() if realtime_monitor else False,
        "quarantine_count": len(file_scanner.get_quarantined_files()),
    })


def _require_license():
    """Return a 403 response if the license is not active, otherwise None."""
    if not license_client.is_activated():
        return jsonify({"success": False, "error": "License required. Please activate Sentinel."}), 403
    return None


def _make_scan_id():
    return str(uuid.uuid4())


# Directories to skip during recursive scans (performance + noise reduction)
_SKIP_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".venv", "venv", "env", ".env",
    "Library", "Photos Library.photoslibrary",
    ".Trash", ".cache", ".npm", ".yarn",
    "Caches", "logs", "log",
    ".gradle", ".m2", ".cargo",
    "site-packages", "dist-packages",
}


def _iter_files(directories, recursive=True, deep=False):
    """Yield file paths efficiently, skipping junk directories."""
    seen = set()
    for root_dir in directories:
        root_path = Path(root_dir)
        if not root_path.is_dir():
            continue
        if recursive:
            stack = [root_path]
            while stack:
                current = stack.pop()
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                skip = entry.name in _SKIP_DIRS
                                if not deep:
                                    skip = skip or entry.name.startswith('.')
                                if not skip:
                                    stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=False):
                                p = entry.path
                                if p not in seen:
                                    seen.add(p)
                                    yield p
                except (PermissionError, OSError):
                    continue
        else:
            try:
                with os.scandir(root_path) as it:
                    for entry in it:
                        if entry.is_file(follow_symlinks=False):
                            p = entry.path
                            if p not in seen:
                                seen.add(p)
                                yield p
            except (PermissionError, OSError):
                continue


def _get_full_scan_dirs(deep=False):
    """Return the list of critical directories for a full system scan."""
    home = Path.home()
    candidates = [
        home / "Downloads",
        home / "Documents",
        home / "Desktop",
        home / "Applications",
        Path("/Applications"),
        Path("/tmp"),
        Path("/var/tmp"),
    ]
    if deep:
        # Include home root for deep scan
        candidates.insert(0, home)
    return [str(p) for p in candidates if p.exists() and p.is_dir()]


# Keep workers low enough that scan doesn't saturate the system
_SCAN_WORKERS = max(2, min(4, os.cpu_count() or 2))


_UPDATE_EVERY = 5  # update session state every N files to cut lock contention


def _run_directory_scan_thread(scan_id, directories, recursive, scan_type):
    """Background thread: pipeline walk + parallel scan."""
    session = scan_sessions[scan_id]

    if isinstance(directories, str):
        directories = [directories]

    target_label = session.get("target", ", ".join(directories))
    is_deep = scan_type == "deep"
    start_time = time.time()

    threats = []
    threats_lock = threading.Lock()
    scanned_counter = [0]
    total_counter = [0]

    # Use a threading.Event for instant cancellation
    cancel_event = threading.Event()

    def _scan_one(file_path):
        if cancel_event.is_set():
            return

        result = file_scanner.scan_file(file_path, scan_type=scan_type)

        # Auto-quarantine any detected threat immediately
        threat_dict = None
        if result:
            original_path = result.path
            base_dict = result.to_dict()
            try:
                q_path = file_scanner.quarantine(original_path, threat_info=base_dict)
                if q_path:
                    result.path = q_path
                    result.quarantined = True
                    result.original_path = original_path
            except Exception:
                pass
            threat_dict = result.to_dict()
            threat_dict["auto_quarantined"] = getattr(result, "quarantined", False)
            threat_dict["original_path"] = getattr(result, "original_path", result.path)

        with threats_lock:
            scanned_counter[0] += 1
            sc = scanned_counter[0]
            if threat_dict:
                threats.append(threat_dict)

        # Update session every N files
        if sc % _UPDATE_EVERY == 0 or threat_dict:
            elapsed = time.time() - start_time
            rate = sc / elapsed if elapsed > 0 else 0
            total_snap = total_counter[0]
            remaining = (total_snap - sc) / rate if rate > 0 and total_snap > sc else 0
            pct = round((sc / total_snap) * 100, 1) if total_snap else 0
            with _scan_session_lock:
                session["files_scanned"] = sc
                session["threats_found"] = len(threats)
                session["threats"] = list(threats)
                session["elapsed"] = round(elapsed, 1)
                session["eta"] = round(remaining, 1)
                session["percent"] = pct
                session["current_file"] = file_path
                session["total_files"] = total_snap

        # Small yield to reduce system load
        time.sleep(0.002)

    _MAX_IN_FLIGHT = _SCAN_WORKERS * 4

    with ThreadPoolExecutor(max_workers=_SCAN_WORKERS) as pool:
        in_flight = []
        try:
            for fp in _iter_files(directories, recursive=recursive, deep=is_deep):
                # Check cancel via both the event and session (for API-triggered cancel)
                if cancel_event.is_set():
                    break
                with _scan_session_lock:
                    if session.get("cancel"):
                        cancel_event.set()
                        break
                with threats_lock:
                    total_counter[0] += 1
                in_flight.append(pool.submit(_scan_one, fp))

                if len(in_flight) >= _MAX_IN_FLIGHT:
                    _, in_flight_set = futures_wait(in_flight, return_when=FIRST_COMPLETED)
                    in_flight = list(in_flight_set)
                    if cancel_event.is_set():
                        break

        except Exception as exc:
            with _scan_session_lock:
                session["status"] = "error"
                session["error"] = str(exc)
            return

        if in_flight and not cancel_event.is_set():
            futures_wait(in_flight)

    final_status = "cancelled" if cancel_event.is_set() else "done"
    elapsed = time.time() - start_time
    with _scan_session_lock:
        session["_finished_at"] = time.time()
        session["status"] = final_status
        session["current_file"] = ""
        session["percent"] = 100
        session["files_scanned"] = scanned_counter[0]
        session["threats_found"] = len(threats)
        session["threats"] = list(threats)
        session["elapsed"] = round(elapsed, 1)
        session["eta"] = 0
        session["completed"] = datetime.utcnow().isoformat() + "Z"
        file_scanner.last_scan_summary = {
            "target": target_label,
            "scan_type": scan_type,
            "files_scanned": scanned_counter[0],
            "threats_found": len(threats),
            "completed": session["completed"],
        }


@app.route("/api/threats/scan/file", methods=["POST"])
def api_scan_file():
    license_error = _require_license()
    if license_error:
        return license_error
    data = request.json or {}
    file_path = data.get("path", "")
    scan_type = data.get("scan_type", "full")
    if not file_path or not os.path.exists(file_path):
        return jsonify({"success": False, "error": "File not found"}), 400

    scan_id = _make_scan_id()
    with _scan_session_lock:
        scan_sessions[scan_id] = {
            "status": "running",
            "target": file_path,
            "scan_type": scan_type,
            "total_files": 1,
            "files_scanned": 0,
            "threats_found": 0,
            "current_file": file_path,
            "percent": 0,
            "elapsed": 0,
            "eta": 0,
            "threats": [],
        }

    result = file_scanner.scan_file(file_path, scan_type=scan_type)
    threat_dict = result.to_dict() if result else None
    summary = {
        "target": file_path,
        "scan_type": scan_type,
        "files_scanned": 1,
        "threats_found": 1 if result else 0,
        "completed": datetime.utcnow().isoformat() + "Z",
    }
    file_scanner.last_scan_summary = summary
    with _scan_session_lock:
        scan_sessions[scan_id].update({
            "status": "done",
            "files_scanned": 1,
            "threats_found": 1 if result else 0,
            "threats": [threat_dict] if threat_dict else [],
            "current_file": "",
            "percent": 100,
        })

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "threat": threat_dict,
        "files_scanned": 1,
        "threats_found": summary["threats_found"],
    })


def _start_scan_session(directories, scan_type, label=None):
    """Create a scan session and start the background thread. Returns scan_id."""
    scan_id = _make_scan_id()
    target_label = label or (directories if isinstance(directories, str) else ", ".join(directories))
    with _scan_session_lock:
        scan_sessions[scan_id] = {
            "status": "running",
            "target": target_label,
            "scan_type": scan_type,
            "total_files": 0,
            "files_scanned": 0,
            "threats_found": 0,
            "current_file": "",
            "percent": 0,
            "elapsed": 0,
            "eta": 0,
            "threats": [],
            "cancel": False,
        }
    t = threading.Thread(
        target=_run_directory_scan_thread,
        args=(scan_id, directories, True, scan_type),
        daemon=True,
    )
    t.start()
    return scan_id


@app.route("/api/threats/scan/full", methods=["POST"])
def api_scan_full():
    license_error = _require_license()
    if license_error:
        return license_error
    data = request.json or {}
    scan_type = data.get("scan_type", "full")
    is_deep = scan_type == "deep"
    dirs = _get_full_scan_dirs(deep=is_deep)
    label = "Deep System Scan" if is_deep else "Full System Scan"
    scan_id = _start_scan_session(dirs, scan_type, label=label)
    return jsonify({"success": True, "scan_id": scan_id, "directories": dirs})


@app.route("/api/threats/scan/directory", methods=["POST"])
def api_scan_directory():
    license_error = _require_license()
    if license_error:
        return license_error
    data = request.json or {}
    directory = data.get("path", "")
    recursive = data.get("recursive", True)
    scan_type = data.get("scan_type", "full")
    if not directory or not os.path.isdir(directory):
        return jsonify({"success": False, "error": "Directory not found"}), 400
    scan_id = _start_scan_session(directory, scan_type)
    return jsonify({"success": True, "scan_id": scan_id})


@app.route("/api/threats/scan/progress/<scan_id>")
def api_scan_progress(scan_id):
    with _scan_session_lock:
        session = scan_sessions.get(scan_id)
    if not session:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    return jsonify({"success": True, **session})


@app.route("/api/threats/scan/cancel/<scan_id>", methods=["POST"])
def api_scan_cancel(scan_id):
    with _scan_session_lock:
        session = scan_sessions.get(scan_id)
        if session:
            session["cancel"] = True
    return jsonify({"success": True})


def _purge_old_scan_sessions():
    """Remove completed scan sessions older than 10 minutes to prevent memory growth."""
    cutoff = time.time() - 600
    with _scan_session_lock:
        to_delete = [
            sid for sid, s in scan_sessions.items()
            if s.get("status") in ("done", "cancelled", "error")
            and s.get("_finished_at", 0) < cutoff
        ]
        for sid in to_delete:
            del scan_sessions[sid]


def _session_gc_worker():
    while True:
        time.sleep(300)
        _purge_old_scan_sessions()


@app.route("/api/threats/results")
def api_threats_results():
    return jsonify(file_scanner.get_results())


@app.route("/api/threats/quarantine", methods=["POST"])
def api_quarantine():
    data = request.json or {}
    file_path = data.get("path", "")
    if not file_path or not os.path.exists(file_path):
        return jsonify({"success": False, "error": "File not found"}), 400
    q_path = file_scanner.quarantine(file_path)
    if q_path:
        scanner.add_alert("quarantine", f"File quarantined: {file_path}")
        return jsonify({"success": True, "quarantine_path": q_path})
    return jsonify({"success": False, "error": "Quarantine failed"})


@app.route("/api/threats/restore", methods=["POST"])
def api_restore():
    data = request.json or {}
    q_path = data.get("path", "")
    if not q_path or not os.path.exists(q_path):
        return jsonify({"success": False, "error": "Quarantined file not found"}), 400
    dest = file_scanner.restore(q_path)
    if dest:
        return jsonify({"success": True, "restored_path": dest})
    return jsonify({"success": False, "error": "Restore failed"})


@app.route("/api/threats/delete", methods=["POST"])
def api_delete():
    data = request.json or {}
    file_path = data.get("path", "")
    if not file_path or not os.path.exists(file_path):
        return jsonify({"success": False, "error": "File not found"}), 400
    if file_scanner.delete_file(file_path):
        # Remove from results if present
        file_scanner.results = [r for r in file_scanner.results if r.path != file_path]
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Delete failed"})


@app.route("/api/threats/ignore", methods=["POST"])
def api_ignore():
    data = request.json or {}
    file_path = data.get("path", "")
    if not file_path:
        return jsonify({"success": False, "error": "Path required"}), 400
    if data.get("unignore"):
        file_scanner.unignore_path(file_path)
    else:
        file_scanner.ignore_path(file_path)
    return jsonify({"success": True, "ignored": file_scanner.get_ignored_paths()})


@app.route("/api/threats/ignore/list")
def api_ignore_list():
    return jsonify({"success": True, "ignored": file_scanner.get_ignored_paths()})


@app.route("/api/threats/quarantine/list")
def api_quarantine_list():
    return jsonify(file_scanner.get_quarantined_files())


@app.route("/api/threats/realtime/start", methods=["POST"])
def api_realtime_start():
    license_error = _require_license()
    if license_error:
        return license_error
    global realtime_monitor
    if realtime_monitor is None:
        realtime_monitor = RealTimeMonitor(file_scanner, on_threat=_on_realtime_threat)
    realtime_monitor.start()
    return jsonify({"success": True, "message": "Real-time protection started"})


@app.route("/api/threats/realtime/stop", methods=["POST"])
def api_realtime_stop():
    global realtime_monitor
    if realtime_monitor:
        realtime_monitor.stop()
    return jsonify({"success": True, "message": "Real-time protection stopped"})


@app.route("/api/threats/intel/status")
def api_intel_status():
    return jsonify({
        "virustotal_api_key_set": bool(file_scanner.virustotal_api_key),
        "malwarebazaar_enabled": True,
        "yara_available": file_scanner.threat_intel.yara_rules is not None,
        "yara_rules_dir": file_scanner.threat_intel.YARA_RULES_DIR,
    })


@app.route("/api/threats/intel/virustotal-key", methods=["POST"])
def api_set_virustotal_key():
    data = request.json or {}
    key = data.get("api_key", "").strip()
    file_scanner.virustotal_api_key = key if key else None
    return jsonify({"success": True, "set": bool(file_scanner.virustotal_api_key)})


@app.route("/api/threats/intel/download-yara", methods=["POST"])
def api_download_yara():
    success = file_scanner.threat_intel.download_signature_base_yara()
    if success:
        file_scanner.threat_intel._load_yara_rules()
    return jsonify({"success": success})


@app.route("/api/threats/intel/check-url", methods=["POST"])
def api_check_url():
    data = request.json or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"success": False, "error": "No URL provided"}), 400
    result = file_scanner.threat_intel.lookup_urlhaus(url)
    return jsonify({"success": True, "result": result})


@app.route("/api/threats/intel/check-host", methods=["POST"])
def api_check_host():
    data = request.json or {}
    host = data.get("host", "").strip()
    if not host:
        return jsonify({"success": False, "error": "No host provided"}), 400
    urlhaus = file_scanner.threat_intel.lookup_urlhaus_host(host)
    threatfox = file_scanner.threat_intel.lookup_threatfox(host, ioc_type="ip" if _is_ip(host) else "domain")
    return jsonify({"success": True, "urlhaus": urlhaus, "threatfox": threatfox})


def _is_ip(value):
    try:
        socket.inet_aton(value)
        return True
    except Exception:
        return False


@app.route("/api/threats/intel/vulns", methods=["POST"])
def api_check_vulns():
    data = request.json or {}
    product = data.get("product", "").strip()
    if not product:
        return jsonify({"success": False, "error": "No product name provided"}), 400

    if product.lower() == "running":
        # Check all running processes against CISA KEV
        seen = set()
        all_matches = []
        for proc in psutil.process_iter(["name"]):
            try:
                name = proc.info.get("name", "")
                if not name or name in seen:
                    continue
                seen.add(name)
                matches = file_scanner.threat_intel.check_cisa_kev(product_name=name)
                for m in matches:
                    m["_matched_process"] = name
                all_matches.extend(matches)
            except Exception:
                pass
        return jsonify({"success": True, "matches": all_matches, "count": len(all_matches)})

    matches = file_scanner.threat_intel.check_cisa_kev(product_name=product)
    return jsonify({"success": True, "matches": matches, "count": len(matches)})


@app.route("/api/threats/intel/update-feeds", methods=["POST"])
def api_update_feeds():
    _update_feeds_now()
    return jsonify({"success": True, "message": "Feeds updated"})


@app.route("/api/threats/intel/feed-status")
def api_feed_status():
    return jsonify({
        "last_feed_update": last_feed_update,
        "feed_update_interval": feed_update_interval,
        "feed_update_running": feed_update_running,
    })


def _run_freshclam():
    try:
        for path in ["/opt/homebrew/bin/freshclam", "/usr/local/bin/freshclam", "/usr/bin/freshclam"]:
            if os.path.exists(path):
                subprocess.run([path], timeout=120, capture_output=True)
                return True
    except Exception:
        pass
    return False


def _update_feeds_now():
    global last_feed_update, feed_update_running
    feed_update_running = True
    try:
        file_scanner.threat_intel.download_cisa_kev()
        file_scanner.threat_intel.download_signature_base_yara()
        file_scanner.threat_intel._load_yara_rules()
        _run_freshclam()
        last_feed_update = datetime.utcnow().isoformat() + "Z"
    except Exception as e:
        print(f"[Feed Update] Error: {e}")
    finally:
        feed_update_running = False


def _feed_update_worker():
    while True:
        _update_feeds_now()
        time.sleep(feed_update_interval)


# === License API ===

@app.route("/api/license/status")
def api_license_status():
    return jsonify(license_client.get_status())


@app.route("/api/license/set-key", methods=["POST"])
def api_license_set_key():
    data = request.json or {}
    license_key = data.get("license_key", "").strip()
    server_url = data.get("server_url", "").strip()
    if not license_key:
        return jsonify({"success": False, "error": "license_key is required"}), 400
    license_client.set_license_key(license_key, server_url)
    return jsonify({"success": True, "message": "License key saved"})


@app.route("/api/license/activate", methods=["POST"])
def api_license_activate():
    result = license_client.activate()
    return jsonify(result)


@app.route("/api/license/validate", methods=["POST"])
def api_license_validate():
    result = license_client.validate()
    return jsonify(result)


@app.route("/api/license/deactivate", methods=["POST"])
def api_license_deactivate():
    result = license_client.deactivate()
    return jsonify(result)


@app.route("/api/license/checkout", methods=["POST"])
def api_license_checkout():
    """Proxy checkout request to the license server."""
    data = request.json or {}
    tier = data.get("tier", "home")
    email = data.get("email", "").strip()
    if not email:
        return jsonify({"success": False, "error": "email is required"}), 400
    try:
        response = requests.post(
            f"{license_client.server_url}/billing/checkout",
            json={"email": email, "tier": tier},
            timeout=15,
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({"success": False, "error": f"License server unreachable: {e}"}), 502


@app.route("/api/license/customer-portal", methods=["POST"])
def api_license_customer_portal():
    """Proxy customer portal request to the license server."""
    data = request.json or {}
    stripe_customer_id = data.get("stripe_customer_id", "").strip()
    if not stripe_customer_id:
        return jsonify({"success": False, "error": "stripe_customer_id is required"}), 400
    try:
        response = requests.post(
            f"{license_client.server_url}/billing/customer-portal",
            json={"stripe_customer_id": stripe_customer_id},
            timeout=15,
        )
        return jsonify(response.json()), response.status_code
    except requests.RequestException as e:
        return jsonify({"success": False, "error": f"License server unreachable: {e}"}), 502


def _check_license():
    """Return True if license is active, otherwise return an error response."""
    if not license_client.is_activated():
        return jsonify({"success": False, "error": "License required. Please activate Sentinel."}), 403
    return None


# ══════════════════════════════════════════════════════════════════════════════
# BETA / ADMIN ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/api/beta/config", methods=["GET"])
def api_beta_config_get():
    return jsonify({
        "admin_url": _ADMIN_SERVER_URL,
        "beta_key": _BETA_KEY,
        "machine_id": _MACHINE_ID,
        "version": _APP_VERSION,
        "configured": bool(_ADMIN_SERVER_URL and _BETA_KEY),
    })


@app.route("/api/beta/configure", methods=["POST"])
def api_beta_configure():
    global _ADMIN_SERVER_URL, _BETA_KEY
    data = request.json or {}
    admin_url = data.get("admin_url", "").strip().rstrip("/")
    beta_key = data.get("beta_key", "").strip().upper()
    if not admin_url or not beta_key:
        return jsonify({"success": False, "error": "admin_url and beta_key required"}), 400

    # Validate key against admin server
    try:
        resp = requests.post(
            f"{admin_url}/api/beta/validate",
            json={"key": beta_key, "machine_id": _MACHINE_ID, "hostname": socket.gethostname()},
            timeout=10,
        )
        result = resp.json()
        if not result.get("valid"):
            return jsonify({"success": False, "error": result.get("error", "Invalid key")}), 403
    except requests.RequestException as e:
        return jsonify({"success": False, "error": f"Cannot reach admin server: {e}"}), 502

    _ADMIN_SERVER_URL = admin_url
    _BETA_KEY = beta_key
    _save_beta_config()
    # Fire an immediate heartbeat so tester appears online right away
    threading.Thread(target=_send_heartbeat, daemon=True).start()
    return jsonify({"success": True, "label": result.get("label", "")})


@app.route("/api/beta/update-check", methods=["GET"])
def api_update_check():
    """Returns pending update info if one is available."""
    return jsonify({
        "current_version": _APP_VERSION,
        "update_available": bool(_pending_update.get("latest_version")),
        "latest_version": _pending_update.get("latest_version", ""),
        "release_notes": _pending_update.get("update_notes", ""),
        "download_url": _pending_update.get("update_url", ""),
        "required": _pending_update.get("update_required", False),
    })


def _cpu_sampler():
    """Prime psutil cpu_percent every 5s so interval=None returns fresh data."""
    psutil.cpu_percent(interval=1)  # initial blocking call to prime
    while True:
        time.sleep(5)
        psutil.cpu_percent(interval=None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18081)
    args = parser.parse_args()

    # Archive alerts from previous session into history log, then start clean
    _history_file = os.path.join(data_dir, "alert_history.json")
    try:
        import json as _json
        from datetime import datetime as _dt

        # Build full alert snapshot from last session
        _old_alerts = []
        for r in file_scanner.results:
            d = r.to_dict()
            _old_alerts.append({"source": "scanner", "session_end": _dt.now().isoformat(), **d})
        try:
            with open(scanner.alerts_file, encoding="utf-8") as _f:
                _net = _json.load(_f)
            for a in (_net or []):
                _old_alerts.append({"source": "network", "session_end": _dt.now().isoformat(), **a})
        except Exception:
            pass

        if _old_alerts:
            # Append to history
            _existing = []
            if os.path.exists(_history_file):
                try:
                    with open(_history_file, encoding="utf-8") as _f:
                        _existing = _json.load(_f)
                except Exception:
                    pass
            _existing.extend(_old_alerts)
            # Keep last 10,000 entries
            _existing = _existing[-10000:]
            with open(_history_file, "w", encoding="utf-8") as _f:
                _json.dump(_existing, _f, indent=2)

        # Now clear active queues for fresh session
        file_scanner.results.clear()
        with open(scanner.alerts_file, "w", encoding="utf-8") as _f:
            _json.dump([], _f)
    except Exception:
        pass

    # Prime CPU sampler so non-blocking reads are accurate
    threading.Thread(target=_cpu_sampler, daemon=True).start()

    # Start background feed updater
    threading.Thread(target=_feed_update_worker, daemon=True).start()

    # Start beta heartbeat (sends telemetry to admin server if configured)
    threading.Thread(target=_heartbeat_worker, daemon=True).start()

    # Garbage-collect stale scan sessions
    threading.Thread(target=_session_gc_worker, daemon=True).start()

    app.run(host="127.0.0.1", port=args.port, debug=False)
