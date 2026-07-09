"""Threat intelligence integration: VirusTotal, MalwareBazaar, and YARA rules."""

import json
import os
import shutil
import time
import zipfile
from pathlib import Path

import requests


try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False


class ThreatIntel:
    """Aggregator for top-tier threat intelligence sources."""

    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files/{hash}"
    MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
    THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"
    CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    YARA_RULES_DIR = None
    yara_rules = None

    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.YARA_RULES_DIR = os.path.join(base_dir, "yara_rules")
        os.makedirs(self.YARA_RULES_DIR, exist_ok=True)
        self._load_yara_rules()

    # === VirusTotal ===
    def lookup_virustotal(self, file_hash, api_key=None):
        if not api_key:
            return None
        try:
            headers = {"x-apikey": api_key}
            url = self.VIRUSTOTAL_URL.format(hash=file_hash)
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                return {
                    "source": "VirusTotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": sum(stats.values()) if stats else 0,
                    "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
                }
            elif response.status_code == 404:
                return {"source": "VirusTotal", "malicious": 0, "not_found": True}
        except Exception as e:
            return {"source": "VirusTotal", "error": str(e)}
        return None

    # === MalwareBazaar ===
    def lookup_malwarebazaar(self, file_hash):
        try:
            response = requests.post(
                self.MALWAREBAZAAR_URL,
                data={"query": "get_info", "hash": file_hash},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    info = data.get("data", [{}])[0]
                    return {
                        "source": "MalwareBazaar",
                        "malware": info.get("signature", "Unknown"),
                        "tags": info.get("tags", []),
                        "file_name": info.get("file_name", ""),
                        "first_seen": info.get("first_seen", ""),
                        "permalink": f"https://bazaar.abuse.ch/sample/{file_hash}/",
                    }
                elif data.get("query_status") == "hash_not_found":
                    return {"source": "MalwareBazaar", "not_found": True}
        except Exception as e:
            return {"source": "MalwareBazaar", "error": str(e)}
        return None

    def download_malwarebazaar_recent(self, limit=50):
        """Download recent malware hashes from MalwareBazaar."""
        try:
            response = requests.post(
                self.MALWAREBAZAAR_URL,
                data={"query": "get_recent", "selector": str(limit)},
                timeout=30,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return data.get("data", [])
        except Exception:
            pass
        return []

    # === ThreatFox ===
    def lookup_threatfox(self, ioc, ioc_type="hash"):
        """Query ThreatFox for IOCs by hash, ip, or domain."""
        try:
            query = {
                "hash": "search_ioc",
                "ip": "search_ioc",
                "domain": "search_ioc",
            }.get(ioc_type)
            if not query:
                return None
            response = requests.post(
                self.THREATFOX_URL,
                json={"query": query, "search_term": ioc},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    hit = data["data"][0]
                    return {
                        "source": "ThreatFox",
                        "malware": hit.get("malware", "Unknown"),
                        "threat_type": hit.get("threat_type", "Unknown"),
                        "first_seen": hit.get("first_seen", ""),
                        "permalink": f"https://threatfox.abuse.ch/ioc/{hit.get('id', '')}/",
                    }
                elif data.get("query_status") == "no_result":
                    return {"source": "ThreatFox", "not_found": True}
        except Exception as e:
            return {"source": "ThreatFox", "error": str(e)}
        return None

    # === URLhaus ===
    def lookup_urlhaus(self, url):
        """Query URLhaus for malicious URLs."""
        try:
            response = requests.post(
                f"{self.URLHAUS_URL}url/",
                data={"url": url},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    return {
                        "source": "URLhaus",
                        "url": data.get("url", url),
                        "threat": data.get("threat", ""),
                        "tags": data.get("tags", []),
                        "payloads": len(data.get("payloads", [])),
                        "permalink": data.get("urlhaus_reference", ""),
                    }
                elif data.get("query_status") == "no_results":
                    return {"source": "URLhaus", "not_found": True}
        except Exception as e:
            return {"source": "URLhaus", "error": str(e)}
        return None

    def lookup_urlhaus_host(self, host):
        """Query URLhaus for malicious host (IP or domain)."""
        try:
            response = requests.post(
                f"{self.URLHAUS_URL}host/",
                data={"host": host},
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                if data.get("query_status") == "ok":
                    urls = data.get("urls", [])
                    if urls:
                        return {
                            "source": "URLhaus",
                            "host": host,
                            "url_count": data.get("url_count", len(urls)),
                            "first_url": urls[0].get("url", ""),
                            "permalink": urls[0].get("urlhaus_reference", ""),
                        }
                elif data.get("query_status") == "no_results":
                    return {"source": "URLhaus", "not_found": True}
        except Exception as e:
            return {"source": "URLhaus", "error": str(e)}
        return None

    # === CISA KEV ===
    def download_cisa_kev(self):
        """Download CISA Known Exploited Vulnerabilities catalog."""
        cache_path = os.path.join(self.base_dir, "cisa_kev.json")
        try:
            response = requests.get(self.CISA_KEV_URL, timeout=30)
            if response.status_code == 200:
                data = response.json()
                with open(cache_path, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                return data
        except Exception:
            pass
        # Fallback to cached file if download fails
        if os.path.exists(cache_path):
            with open(cache_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return {"vulnerabilities": []}

    def check_cisa_kev(self, product_name=None, cve_id=None):
        """Check if product or CVE is in CISA KEV list."""
        data = self.download_cisa_kev()
        matches = []
        for vuln in data.get("vulnerabilities", []):
            if cve_id and vuln.get("cveID", "").lower() == cve_id.lower():
                matches.append(vuln)
            elif product_name and product_name.lower() in vuln.get("product", "").lower():
                matches.append(vuln)
        return matches

    # === YARA Rules ===
    def _write_default_rules(self):
        """Create a small built-in YARA rule set."""
        rule_path = os.path.join(self.YARA_RULES_DIR, "builtin.yar")
        rules = r"""
rule suspicious_powershell_encoded
{
    strings:
        $a = /powershell[ \t]+-(enc|encodedcommand)/ nocase
        $b = /powershell[ \t]+-w[ \t]+hidden/ nocase
    condition:
        any of them
}

rule suspicious_cmd
{
    strings:
        $a = "cmd.exe /c" nocase
        $b = "cmd /c" nocase
        $c = "powershell.exe" nocase
    condition:
        any of them
}

rule eicar_test
{
    strings:
        $a = {58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24 45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2d 41 4e 54 49 56 49 52 55 53 2d 54 45 53 54 2d 46 49 4c 45 21 24 48 2b 48 2A}
    condition:
        any of them
}

rule suspicious_wscript
{
    strings:
        $a = "Wscript.Shell" nocase
        $b = "Shell.Application" nocase
        $c = "CreateObject" nocase
    condition:
        any of them
}

rule ransomware_note_pattern
{
    strings:
        $a = /all your files.*(encrypted|locked)/ nocase
        $b = "bitcoin" nocase
        $c = "decrypt" nocase
    condition:
        2 of them
}
"""
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rules)
        return rule_path

    def download_signature_base_yara(self):
        """Download Florian Roth's signature-base YARA rules."""
        try:
            url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
            zip_path = os.path.join(self.base_dir, "signature-base.zip")
            extract_dir = os.path.join(self.base_dir, "signature-base-temp")

            response = requests.get(url, timeout=60)
            if response.status_code != 200:
                return False

            with open(zip_path, "wb") as f:
                f.write(response.content)

            with zipfile.ZipFile(zip_path, "r") as z:
                z.extractall(extract_dir)

            yara_dir = os.path.join(extract_dir, "signature-base-master", "yara")
            if os.path.exists(yara_dir):
                count = 0
                for yar_file in Path(yara_dir).glob("*.yar"):
                    dest = os.path.join(self.YARA_RULES_DIR, yar_file.name)
                    shutil.copy(str(yar_file), dest)
                    count += 1
                # Clean up
                os.remove(zip_path)
                shutil.rmtree(extract_dir)
                return count > 0
        except Exception:
            pass
        return False

    def _load_yara_rules(self):
        if not YARA_AVAILABLE:
            self.yara_rules = None
            return

        # Ensure default rules exist
        self._write_default_rules()

        # Try to compile all .yar files
        rule_files = {}
        for yar_file in Path(self.YARA_RULES_DIR).glob("*.yar"):
            rule_files[yar_file.name] = str(yar_file)

        if not rule_files:
            self.yara_rules = None
            return

        try:
            self.yara_rules = yara.compile(filepaths=rule_files)
        except Exception:
            # If compilation fails (e.g., duplicate rule names), load builtin only
            try:
                builtin = os.path.join(self.YARA_RULES_DIR, "builtin.yar")
                self.yara_rules = yara.compile(filepath=builtin)
            except Exception:
                self.yara_rules = None

    def scan_with_yara(self, file_path):
        if not self.yara_rules:
            return None
        try:
            matches = self.yara_rules.match(file_path)
            if matches:
                return [
                    {"rule": m.rule, "tags": m.tags, "strings": [str(s) for s in (m.strings or [])[:3]]}
                    for m in matches
                ]
        except Exception:
            pass
        return None
