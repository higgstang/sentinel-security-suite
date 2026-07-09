"""Malware scanning, heuristic detection, quarantine, and real-time file monitoring."""

import hashlib
import json as _json
import math
import os
import platform
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

from threat_intel import ThreatIntel
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


def _sha256_file(file_path):
    """Compute SHA256 hash for a file."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


class ThreatResult:
    def __init__(self, path, threat_type, description, severity="medium", file_size=None, file_hash=None):
        self.path = path
        self.threat_type = threat_type
        self.description = description
        self.severity = severity
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.file_size = file_size if file_size is not None else 0
        self.file_hash = file_hash or ""
        if file_size is None or not file_hash:
            try:
                if os.path.isfile(path):
                    if file_size is None:
                        self.file_size = os.path.getsize(path)
                    if not file_hash:
                        self.file_hash = _sha256_file(path)
            except Exception:
                pass

    def to_dict(self):
        return {
            "path": self.path,
            "threat_type": self.threat_type,
            "description": self.description,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
        }


# Extensions that are safe to skip in full (non-deep) scans — pure media/data
_SKIP_EXTENSIONS_FULL = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".tiff", ".ico",
    ".mp3", ".mp4", ".m4a", ".m4v", ".mov", ".avi", ".mkv", ".flac", ".wav", ".ogg", ".aac",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
    ".ttf", ".otf", ".woff", ".woff2",
    ".sqlite", ".db",
}


class FileScanner:
    """Scan files and directories for malware using multiple methods."""

    # Known suspicious extensions and patterns
    SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".sh", ".app", ".pkg", ".dmg"}
    SCRIPT_EXTENSIONS = {".vbs", ".js", ".ps1", ".bat", ".cmd", ".sh", ".wsf", ".hta"}

    # Heuristic patterns (common malicious indicators)
    SUSPICIOUS_PATTERNS = [
        (r"powershell\s+-enc\s+", "Encoded PowerShell command"),
        (r"cmd\.exe\s+/c\s+", "Suspicious cmd execution"),
        (r"wscript\.shell", "Windows Script Host usage"),
        (r"CreateObject\s*\(\s*\"Wscript\.Shell\"", "WScript.Shell object creation"),
        (r"Shell\.Application", "Shell.Application object"),
        (r"eval\s*\(", "JavaScript eval usage"),
        (r"document\.write\s*\(\s*unescape", "Document write with unescape"),
        (r"<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>", "Embedded script tag"),
        (r"reg\s+add\s+.*\\Run", "Registry run key persistence"),
        (r"netsh\s+advfirewall\s+set\s+allprofiles\s+state\s+off", "Firewall disable attempt"),
        (r"taskkill\s+/f\s+/im\s+.*security", "Security process termination"),
        (r"CreateRemoteThread", "Process injection API"),
        (r"VirtualAllocEx", "Process memory allocation"),
        (r"WriteProcessMemory", "Process memory writing"),
        (r"\\x\d{2}\\x\d{2}\\x\d{2}", "Hex-encoded payload"),
    ]

    # Common malware hashes (SHA256) - tiny sample set for demonstration
    KNOWN_MALWARE_HASHES = {
        # EICAR test file
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test File",
    }

    def __init__(self, quarantine_dir=None, base_dir=None):
        if base_dir is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
        if quarantine_dir is None:
            quarantine_dir = os.path.join(base_dir, "quarantine")
        self.quarantine_dir = quarantine_dir
        os.makedirs(self.quarantine_dir, exist_ok=True)
        self.results = []
        self.ignored = set()
        self.last_scan_summary = {}
        self.threat_intel = ThreatIntel(base_dir)
        self.virustotal_api_key = None
        self.clamav_available = self._check_clamav()

    def _find_clamav(self):
        """Find clamscan executable in common locations."""
        paths = ["clamscan"]
        common_paths = [
            "/opt/homebrew/bin/clamscan",
            "/usr/local/bin/clamscan",
            "/opt/local/bin/clamscan",
            "/usr/bin/clamscan",
        ]
        paths.extend(common_paths)
        for c in paths:
            try:
                result = subprocess.run([c, "--version"], capture_output=True, timeout=5)
                if result.returncode == 0:
                    return c
            except Exception:
                continue
        return None

    def _check_clamav(self):
        """Check if ClamAV is installed."""
        return self._find_clamav() is not None

    def _sha256(self, file_path):
        return _sha256_file(file_path)

    def is_ignored(self, file_path):
        """Check if a file or its parent directory is ignored."""
        if file_path in self.ignored:
            return True
        for ignored in self.ignored:
            if file_path == ignored or file_path.startswith(ignored + os.sep):
                return True
        return False

    def ignore_path(self, file_path):
        """Add a path to the ignore list."""
        self.ignored.add(file_path)
        return True

    def unignore_path(self, file_path):
        """Remove a path from the ignore list."""
        self.ignored.discard(file_path)
        return True

    def get_ignored_paths(self):
        return sorted(list(self.ignored))

    def delete_file(self, file_path):
        """Permanently delete a file."""
        if not os.path.isfile(file_path):
            return False
        try:
            os.remove(file_path)
            return True
        except Exception:
            return False

    def _scan_with_clamav(self, path):
        """Run ClamAV scan if available."""
        clamscan = self._find_clamav()
        if not clamscan:
            return None
        try:
            result = subprocess.run(
                [clamscan, "--no-summary", "--infected", path],
                capture_output=True,
                text=True,
                timeout=120,
            )
            # clamscan returns 1 when infected
            if result.returncode == 1:
                output = result.stdout.strip() or result.stderr.strip()
                # Parse: "path: Threat.Name FOUND"
                match = re.search(r":\s*(.+)\s+FOUND", output)
                name = match.group(1).strip() if match else "Unknown malware"
                return ThreatResult(path, "virus", f"ClamAV detected: {name}", "high")
        except Exception:
            pass
        return None

    def _make_file_ctx(self, file_path):
        """Build a shared context: compute SHA256 + grab first 64KB in one pass, then text."""
        ctx = {"hash": None, "size": 0, "text": None, "raw": None}
        try:
            ctx["size"] = os.path.getsize(file_path)
        except Exception:
            return ctx
        # Single binary pass: hash the whole file, keep first 64KB for binary analysis
        try:
            h = hashlib.sha256()
            first_chunk = b""
            with open(file_path, "rb") as f:
                chunk = f.read(65536)
                if chunk:
                    first_chunk = chunk
                    h.update(chunk)
                    for chunk in iter(lambda: f.read(65536), b""):
                        h.update(chunk)
            ctx["hash"] = h.hexdigest()
            ctx["raw"] = first_chunk
        except Exception:
            pass
        # Text pass only for files small enough to pattern-scan
        if 0 < ctx["size"] <= 50 * 1024 * 1024:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    ctx["text"] = f.read()
            except Exception:
                pass
        return ctx

    def _signature_scan(self, file_path, ctx=None):
        """Check file hash against known malware database."""
        file_hash = ctx["hash"] if ctx else self._sha256(file_path)
        if file_hash and file_hash in self.KNOWN_MALWARE_HASHES:
            name = self.KNOWN_MALWARE_HASHES[file_hash]
            return ThreatResult(file_path, "known_malware", f"Known malware hash match: {name}", "critical",
                                file_size=ctx["size"] if ctx else None, file_hash=file_hash)
        return None

    def _heuristic_scan(self, file_path, ctx=None):
        """Apply heuristic rules to detect suspicious content."""
        size = ctx["size"] if ctx else 0
        if not size:
            try:
                size = os.path.getsize(file_path)
            except Exception:
                return None

        if size > 50 * 1024 * 1024:  # 50 MB
            return None

        ext = os.path.splitext(file_path)[1].lower()
        threats = []

        # Double extension trick
        if re.search(r"\.(pdf|doc|docx|xls|xlsx|txt|jpg|png)\.(exe|zip|scr|com|vbs|js)$", file_path, re.I):
            threats.append(ThreatResult(file_path, "suspicious_extension", "Double extension masquerading", "high"))

        # Executable with suspicious name
        base = os.path.basename(file_path).lower()
        if ext in {".exe", ".dll", ".scr", ".com", ".app"}:
            if any(x in base for x in ["crack", "keygen", "patch", "activator", "hack", "loader", "miner"]):
                threats.append(ThreatResult(file_path, "suspicious_name", "Executable with suspicious name", "high"))

        # Pattern scan using cached text content
        content = (ctx["text"] if ctx else None)
        if content is None and size <= 50 * 1024 * 1024:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception:
                pass

        if content:
            for pattern, desc in self.SUSPICIOUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    label = "suspicious_script" if ext in self.SCRIPT_EXTENSIONS else "suspicious_content"
                    severity = "high" if ext in self.SCRIPT_EXTENSIONS else "medium"
                    if not any(t.description == desc for t in threats):
                        threats.append(ThreatResult(file_path, label, desc, severity))

        if threats:
            r = threats[0]
            if ctx:
                r.file_size = ctx["size"]
                r.file_hash = ctx["hash"] or ""
            return r
        return None

    def _intel_scan(self, file_path, ctx=None):
        """Use threat intelligence feeds and YARA to detect threats."""
        file_hash = ctx["hash"] if ctx else self._sha256(file_path)

        # VirusTotal (if API key configured)
        if self.virustotal_api_key:
            vt = self.threat_intel.lookup_virustotal(file_hash, self.virustotal_api_key)
            if vt and vt.get("malicious", 0) > 0:
                desc = f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged this file"
                return ThreatResult(file_path, "virustotal", desc, "critical")

        # MalwareBazaar
        mb = self.threat_intel.lookup_malwarebazaar(file_hash)
        if mb and not mb.get("not_found") and not mb.get("error"):
            desc = f"MalwareBazaar: known malware ({mb.get('malware', 'Unknown')})"
            return ThreatResult(file_path, "malwarebazaar", desc, "critical")

        # ThreatFox
        tf = self.threat_intel.lookup_threatfox(file_hash, "hash")
        if tf and not tf.get("not_found") and not tf.get("error"):
            desc = f"ThreatFox: {tf.get('malware', 'Unknown')} ({tf.get('threat_type', 'Unknown')})"
            return ThreatResult(file_path, "threatfox", desc, "critical")

        # YARA rules
        yara_matches = self.threat_intel.scan_with_yara(file_path)
        if yara_matches:
            rules = ", ".join(m["rule"] for m in yara_matches)
            desc = f"YARA match: {rules}"
            return ThreatResult(file_path, "yara", desc, "high",
                                file_size=ctx["size"] if ctx else None, file_hash=file_hash)

        return None

    def _deep_scan(self, file_path, ctx=None):
        """Deep scan: inspect all file types, larger files, and binary entropy."""
        threats = []
        ext = os.path.splitext(file_path)[1].lower()

        # Double extension trick (all files)
        if re.search(r"\.(pdf|doc|docx|xls|xlsx|txt|jpg|png)\.(exe|zip|scr|com|vbs|js)$", file_path, re.I):
            threats.append(ThreatResult(file_path, "suspicious_extension", "Double extension masquerading", "high"))

        # Suspicious executable name
        base = os.path.basename(file_path).lower()
        if ext in {".exe", ".dll", ".scr", ".com", ".app"}:
            if any(x in base for x in ["crack", "keygen", "patch", "activator", "hack", "loader", "miner"]):
                threats.append(ThreatResult(file_path, "suspicious_name", "Executable with suspicious name", "high"))

        size = ctx["size"] if ctx else 0
        if size > 0 and size <= 200 * 1024 * 1024:
            # Text-mode pattern scan using cached content
            content = ctx["text"] if ctx else None
            if content is None:
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    pass
            if content:
                for pattern, desc in self.SUSPICIOUS_PATTERNS:
                    if re.search(pattern, content, re.IGNORECASE):
                        if not any(t.description == desc for t in threats):
                            threats.append(ThreatResult(file_path, "suspicious_content", desc, "high"))

            # Binary entropy / shellcode heuristics using cached raw chunk
            raw = ctx["raw"] if ctx else None
            if raw is None:
                try:
                    with open(file_path, "rb") as f:
                        raw = f.read(65536)
                except Exception:
                    pass
            if raw and len(raw) >= 256:
                byte_counts = [0] * 256
                for b in raw:
                    byte_counts[b] += 1
                n = len(raw)
                entropy = -sum((c / n) * math.log2(c / n) for c in byte_counts if c > 0)
                if entropy > 7.2:
                    if not any(t.threat_type == "high_entropy" for t in threats):
                        threats.append(ThreatResult(
                            file_path, "high_entropy",
                            f"High entropy content ({entropy:.2f} bits) — possible packed/encrypted payload",
                            "medium"
                        ))
                if raw[:2] == b"MZ" and ext not in {".exe", ".dll", ".scr", ".com", ".sys"}:
                    threats.append(ThreatResult(
                        file_path, "embedded_executable",
                        "MZ/PE executable header found in non-executable file",
                        "high"
                    ))
                if raw[:4] == b"\x7fELF" and ext not in {".so", "", ".elf"}:
                    threats.append(ThreatResult(
                        file_path, "embedded_executable",
                        "ELF executable header found in unexpected file type",
                        "high"
                    ))

        if threats:
            r = threats[0]
            if ctx:
                r.file_size = ctx["size"]
                r.file_hash = ctx["hash"] or ""
            return r
        return None

    def scan_file(self, file_path, scan_type="full"):
        """Scan a single file with all available methods.

        scan_type: 'quick' (hash only), 'full' (all engines), 'deep' (all engines + binary analysis).
        """
        if not os.path.exists(file_path):
            return None
        if self.is_ignored(file_path):
            return None

        ext = os.path.splitext(file_path)[1].lower()

        # Quick mode: hash/signature only, no content read
        if scan_type == "quick":
            ctx = {"hash": self._sha256(file_path), "size": 0, "text": None, "raw": None}
            result = self._signature_scan(file_path, ctx)
            if result:
                self.results.append(result)
                return result
            return None

        # Full/deep: skip pure media files unless deep scan
        if scan_type != "deep" and ext in _SKIP_EXTENSIONS_FULL:
            return None

        # Build shared file context once (one hash + one read)
        ctx = self._make_file_ctx(file_path)

        # Threat intelligence
        result = self._intel_scan(file_path, ctx)
        if result:
            self.results.append(result)
            return result

        # ClamAV
        result = self._scan_with_clamav(file_path)
        if result:
            self.results.append(result)
            return result

        # Signature/hash
        result = self._signature_scan(file_path, ctx)
        if result:
            self.results.append(result)
            return result

        # Deep mode: binary + entropy analysis
        if scan_type == "deep":
            result = self._deep_scan(file_path, ctx)
            if result:
                self.results.append(result)
                return result
            return None

        # Full mode: heuristics
        result = self._heuristic_scan(file_path, ctx)
        if result:
            self.results.append(result)
            return result

        return None

    def scan_directory(self, directory, recursive=True, scan_type="full"):
        """Scan all files in a directory."""
        found = []
        if recursive:
            pattern = "**/*"
        else:
            pattern = "*"

        self.last_scan_summary = {
            "target": directory,
            "scan_type": scan_type,
            "files_scanned": 0,
            "threats_found": 0,
            "started": datetime.utcnow().isoformat() + "Z",
            "completed": None,
        }

        for file_path in Path(directory).glob(pattern):
            if file_path.is_file():
                self.last_scan_summary["files_scanned"] += 1
                result = self.scan_file(str(file_path), scan_type=scan_type)
                if result:
                    found.append(result)
                    self.last_scan_summary["threats_found"] += 1

        self.last_scan_summary["completed"] = datetime.utcnow().isoformat() + "Z"
        return found

    def quarantine(self, file_path, threat_info=None):
        """Move a file to quarantine and return new path."""
        if not os.path.exists(file_path):
            return None
        filename = os.path.basename(file_path)
        timestamp = int(time.time() * 1000)
        quarantine_path = os.path.join(self.quarantine_dir, f"{timestamp}_{filename}")
        shutil.move(file_path, quarantine_path)
        # Write sidecar metadata
        meta = {
            "original_path": file_path,
            "quarantined_at": datetime.utcnow().isoformat() + "Z",
            "threat_type": threat_info.get("threat_type") if threat_info else None,
            "description": threat_info.get("description") if threat_info else None,
            "severity": threat_info.get("severity") if threat_info else None,
            "file_hash": threat_info.get("file_hash") if threat_info else None,
            "file_size": threat_info.get("file_size") if threat_info else None,
        }
        try:
            with open(quarantine_path + ".meta.json", "w") as f:
                _json.dump(meta, f)
        except Exception:
            pass
        return quarantine_path

    def restore(self, quarantine_path, original_dir=None):
        """Restore a quarantined file."""
        if not os.path.exists(quarantine_path):
            return None
        filename = os.path.basename(quarantine_path)
        # Remove timestamp prefix
        if "_" in filename:
            filename = filename.split("_", 1)[1]
        if original_dir:
            dest = os.path.join(original_dir, filename)
        else:
            dest = os.path.join(os.path.expanduser("~"), "Restored", filename)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.move(quarantine_path, dest)
        # Remove sidecar metadata
        meta_path = quarantine_path + ".meta.json"
        try:
            if os.path.exists(meta_path):
                os.remove(meta_path)
        except Exception:
            pass
        return dest

    def get_results(self):
        return [r.to_dict() for r in self.results]

    def get_quarantined_files(self):
        files = []
        if not os.path.exists(self.quarantine_dir):
            return files
        for name in sorted(os.listdir(self.quarantine_dir), reverse=True):
            if name.endswith(".meta.json"):
                continue
            path = os.path.join(self.quarantine_dir, name)
            if not os.path.isfile(path):
                continue
            entry = {
                "path": path,
                "name": name,
                "size": os.path.getsize(path),
                "timestamp": datetime.utcfromtimestamp(os.path.getmtime(path)).isoformat() + "Z",
                "original_path": None,
                "threat_type": None,
                "description": None,
                "severity": None,
                "file_hash": None,
            }
            meta_path = path + ".meta.json"
            if os.path.isfile(meta_path):
                try:
                    with open(meta_path) as f:
                        meta = _json.load(f)
                    entry.update({
                        "original_path": meta.get("original_path"),
                        "threat_type": meta.get("threat_type"),
                        "description": meta.get("description"),
                        "severity": meta.get("severity"),
                        "file_hash": meta.get("file_hash"),
                    })
                except Exception:
                    pass
            files.append(entry)
        return files


class RealTimeMonitor(FileSystemEventHandler):
    """Watch directories for suspicious file activity."""

    def __init__(self, scanner, watched_dirs=None, on_threat=None):
        self.scanner = scanner
        self.on_threat = on_threat
        self.observer = None
        self.watched_dirs = watched_dirs or [os.path.expanduser("~")]
        self._running = False

    def on_created(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory:
            return
        self._check_file(event.src_path)

    def _check_file(self, path):
        try:
            # Skip quarantine and system files
            if self.scanner.quarantine_dir in path:
                return
            result = self.scanner.scan_file(path)
            if result and self.on_threat:
                self.on_threat(result.to_dict())
        except Exception:
            pass

    def start(self):
        if self._running:
            return
        self.observer = Observer()
        for d in self.watched_dirs:
            if os.path.exists(d):
                self.observer.schedule(self, d, recursive=True)
        self.observer.start()
        self._running = True

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        self._running = False

    def is_running(self):
        return self._running
