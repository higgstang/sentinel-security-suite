"""Basic integration tests for the license server."""

import json
import os
import sys
import time

import requests

BASE_URL = os.environ.get("LICENSE_SERVER_URL", "http://127.0.0.1:5000")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "sentinel-admin-token")


def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"}


def test_health():
    r = requests.get(f"{BASE_URL}/health")
    assert r.status_code == 200, f"Health failed: {r.text}"
    assert r.json()["status"] == "ok"
    print("[PASS] health")


def test_generate_license():
    payload = {
        "email": "test@example.com",
        "tier": "pro",
        "max_devices": 3,
        "days": 365,
    }
    r = requests.post(f"{BASE_URL}/admin/generate-license", json=payload, headers=admin_headers())
    assert r.status_code == 200, f"Generate failed: {r.text}"
    data = r.json()
    assert data["success"] is True
    assert data["tier"] == "pro"
    assert data["max_devices"] == 3
    assert "license_key" in data
    print("[PASS] generate-license")
    return data["license_key"]


def test_activate(license_key, fingerprint):
    payload = {
        "license_key": license_key,
        "fingerprint": fingerprint,
        "device_name": "Test Machine",
        "platform": "macOS",
    }
    r = requests.post(f"{BASE_URL}/activate", json=payload)
    assert r.status_code == 200, f"Activate failed: {r.text}"
    data = r.json()
    assert data["success"] is True
    print("[PASS] activate")


def test_validate(license_key, fingerprint):
    payload = {"license_key": license_key, "fingerprint": fingerprint}
    r = requests.post(f"{BASE_URL}/validate", json=payload)
    assert r.status_code == 200, f"Validate failed: {r.text}"
    data = r.json()
    assert data["success"] is True
    assert data["valid"] is True
    print("[PASS] validate")


def test_max_devices(license_key):
    # Activate 3 devices (limit)
    for i in range(3):
        payload = {
            "license_key": license_key,
            "fingerprint": f"device-{i}",
            "device_name": f"Device {i}",
        }
        r = requests.post(f"{BASE_URL}/activate", json=payload)
        assert r.status_code == 200, f"Activate device {i} failed: {r.text}"

    # 4th should fail
    payload = {"license_key": license_key, "fingerprint": "device-3"}
    r = requests.post(f"{BASE_URL}/activate", json=payload)
    assert r.status_code == 403, f"Expected 403 for max devices, got {r.status_code}: {r.text}"
    print("[PASS] max-device limit")


def test_deactivate(license_key, fingerprint):
    payload = {"license_key": license_key, "fingerprint": fingerprint}
    r = requests.post(f"{BASE_URL}/deactivate", json=payload)
    assert r.status_code == 200, f"Deactivate failed: {r.text}"
    data = r.json()
    assert data["success"] is True
    print("[PASS] deactivate")


def test_revoke(license_key):
    payload = {"license_key": license_key}
    r = requests.post(f"{BASE_URL}/admin/revoke", json=payload, headers=admin_headers())
    assert r.status_code == 200, f"Revoke failed: {r.text}"
    data = r.json()
    assert data["success"] is True
    print("[PASS] revoke")


def main():
    # Wait for server to be ready
    for _ in range(10):
        try:
            test_health()
            break
        except requests.exceptions.ConnectionError:
            time.sleep(0.5)
    else:
        print("[FAIL] Could not connect to license server")
        sys.exit(1)

    license_key = test_generate_license()
    fingerprint = "test-device-123"
    test_activate(license_key, fingerprint)
    test_validate(license_key, fingerprint)

    # Test a separate license for max devices
    max_key = test_generate_license()
    test_max_devices(max_key)

    test_deactivate(license_key, fingerprint)
    test_revoke(license_key)

    print("\nAll tests passed.")


if __name__ == "__main__":
    main()
