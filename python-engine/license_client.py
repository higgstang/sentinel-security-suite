"""License client for Sentinel app.

Manages local license key, device fingerprint, and communication with the
self-hosted Sentinel license server.
"""

import hashlib
import json
import os
import platform
import uuid

import requests


class LicenseClient:
    """Client for license activation, validation, and deactivation."""

    LICENSE_FILE = "license.json"

    def __init__(self, base_dir, server_url=None):
        self.base_dir = base_dir
        # If base_dir is already a writable data dir (packaged app), use it directly
        self.data_dir = base_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.license_path = os.path.join(self.data_dir, self.LICENSE_FILE)
        self.server_url = server_url or os.environ.get(
            "LICENSE_SERVER_URL", "http://127.0.0.1:5000"
        )
        self._fingerprint = self._get_device_fingerprint()
        self._license = self._load_license()

    def _get_device_fingerprint(self):
        """Create a stable device fingerprint from system identifiers."""
        try:
            mac = uuid.getnode()
            node = f"{mac}-{platform.node()}-{platform.system()}-{platform.machine()}"
            return hashlib.sha256(node.encode("utf-8")).hexdigest()
        except Exception:
            return hashlib.sha256(str(uuid.getnode()).encode("utf-8")).hexdigest()

    def _load_license(self):
        if not os.path.exists(self.license_path):
            return None
        try:
            with open(self.license_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_license(self, data):
        with open(self.license_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _clear_license(self):
        if os.path.exists(self.license_path):
            os.remove(self.license_path)
        self._license = None

    def get_license_key(self):
        if self._license:
            return self._license.get("license_key")
        return None

    def set_license_key(self, license_key, server_url=None):
        if server_url:
            self.server_url = server_url
        self._license = {"license_key": license_key, "activated": False}
        self._save_license(self._license)

    def activate(self):
        """Activate this device with the license server."""
        if not self._license or not self._license.get("license_key"):
            return {"success": False, "error": "No license key configured"}

        payload = {
            "license_key": self._license["license_key"],
            "fingerprint": self._fingerprint,
            "device_name": platform.node(),
            "platform": platform.system(),
        }
        try:
            response = requests.post(
                f"{self.server_url}/activate", json=payload, timeout=15
            )
            data = response.json()
            if data.get("success"):
                self._license["activated"] = True
                self._license["tier"] = data.get("license", {}).get("tier")
                self._license["max_devices"] = data.get("license", {}).get("max_devices")
                self._save_license(self._license)
            return data
        except requests.RequestException as e:
            return {"success": False, "error": f"License server unreachable: {e}"}

    def validate(self):
        """Validate the current license and device activation."""
        if not self._license or not self._license.get("license_key"):
            return {"success": False, "error": "No license key configured"}

        if not self._license.get("activated"):
            return {"success": False, "error": "License not activated"}

        payload = {
            "license_key": self._license["license_key"],
            "fingerprint": self._fingerprint,
        }
        try:
            response = requests.post(
                f"{self.server_url}/validate", json=payload, timeout=15
            )
            return response.json()
        except requests.RequestException as e:
            return {"success": False, "error": f"License server unreachable: {e}"}

    def deactivate(self):
        """Deactivate this device on the license server."""
        if not self._license or not self._license.get("license_key"):
            return {"success": False, "error": "No license key configured"}

        payload = {
            "license_key": self._license["license_key"],
            "fingerprint": self._fingerprint,
        }
        try:
            response = requests.post(
                f"{self.server_url}/deactivate", json=payload, timeout=15
            )
            data = response.json()
            if data.get("success"):
                self._clear_license()
            return data
        except requests.RequestException as e:
            return {"success": False, "error": f"License server unreachable: {e}"}

    def is_activated(self):
        return self._license is not None and self._license.get("activated") is True

    def get_status(self):
        return {
            "license_key": self.get_license_key(),
            "fingerprint": self._fingerprint,
            "activated": self.is_activated(),
            "tier": self._license.get("tier") if self._license else None,
            "max_devices": self._license.get("max_devices") if self._license else None,
            "expires_at": self._license.get("expires_at") if self._license else None,
            "server_url": self.server_url,
        }
