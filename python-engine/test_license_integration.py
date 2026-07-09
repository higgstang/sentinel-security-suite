"""Integration test for license activation in the Sentinel engine.

Starts the license server, starts the engine, activates a license, and
checks that protected endpoints work only with an active license.
"""

import json
import os
import subprocess
import sys
import time

import requests

LICENSE_SERVER_URL = "http://127.0.0.1:5001"
ENGINE_URL = "http://127.0.0.1:18082"
ADMIN_TOKEN = "sentinel-admin-token"


def wait_for_server(url, timeout=20):
    for _ in range(timeout * 2):
        try:
            requests.get(url, timeout=1)
            return True
        except requests.exceptions.ConnectionError:
            time.sleep(0.5)
    return False


def start_license_server():
    # Clean up any previous state
    for f in ["licenses.db", "private_key.pem", "public_key.pem"]:
        if os.path.exists(f):
            os.remove(f)
    return subprocess.Popen(
        [sys.executable, "../license-server/app.py", "--port", "5001"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def start_engine():
    env = os.environ.copy()
    env["LICENSE_SERVER_URL"] = LICENSE_SERVER_URL
    return subprocess.Popen(
        [sys.executable, "main.py", "--port", "18082"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def generate_license():
    headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
    payload = {
        "email": "integration@test.com",
        "tier": "home",
        "max_devices": 1,
        "days": 365,
    }
    r = requests.post(f"{LICENSE_SERVER_URL}/admin/generate-license", json=payload, headers=headers)
    r.raise_for_status()
    return r.json()["license_key"]


def main():
    print("Starting license server...")
    ls_proc = start_license_server()
    if not wait_for_server(LICENSE_SERVER_URL):
        print("License server did not start")
        ls_proc.terminate()
        sys.exit(1)

    print("Starting Sentinel engine...")
    engine_proc = start_engine()
    if not wait_for_server(ENGINE_URL):
        print("Engine did not start")
        engine_proc.terminate()
        ls_proc.terminate()
        sys.exit(1)

    try:
        # 1. Scan should fail without license
        print("\nTesting scan without license...")
        r = requests.post(f"{ENGINE_URL}/api/threats/scan/file", json={"path": "/etc/hosts"})
        assert r.status_code == 403, f"Expected 403, got {r.status_code}: {r.text}"
        print("[PASS] scan blocked without license")

        # 2. Generate and set license
        print("\nGenerating license...")
        license_key = generate_license()
        print(f"License key: {license_key}")

        r = requests.post(f"{ENGINE_URL}/api/license/set-key", json={"license_key": license_key})
        assert r.status_code == 200 and r.json()["success"], f"Set key failed: {r.text}"
        print("[PASS] set license key")

        r = requests.post(f"{ENGINE_URL}/api/license/activate")
        assert r.status_code == 200 and r.json()["success"], f"Activate failed: {r.text}"
        print("[PASS] activate license")

        # 3. Scan should now work
        print("\nTesting scan with license...")
        r = requests.post(f"{ENGINE_URL}/api/threats/scan/file", json={"path": "/etc/hosts"})
        assert r.status_code == 200, f"Scan failed: {r.status_code} {r.text}"
        print("[PASS] scan allowed with license")

        # 4. Validate license
        r = requests.post(f"{ENGINE_URL}/api/license/validate")
        assert r.status_code == 200 and r.json()["success"], f"Validate failed: {r.text}"
        print("[PASS] validate license")

    finally:
        engine_proc.terminate()
        ls_proc.terminate()
        try:
            engine_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            engine_proc.kill()
        try:
            ls_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            ls_proc.kill()

    print("\nAll integration tests passed.")


if __name__ == "__main__":
    main()
