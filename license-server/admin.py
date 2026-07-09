"""Admin CLI for managing Sentinel licenses.

Usage:
    python admin.py generate --email user@example.com --tier pro --max-devices 3 --days 365
    python admin.py info --license-key XXXX-XXXX-XXXX-XXXX
    python admin.py revoke --license-key XXXX-XXXX-XXXX-XXXX
    python admin.py list
"""

import argparse
import os
import sys

import requests

BASE_URL = os.environ.get("LICENSE_SERVER_URL", "http://127.0.0.1:5000")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "sentinel-admin-token")


def headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}", "Content-Type": "application/json"}


def generate_license(args):
    payload = {
        "email": args.email,
        "name": args.name,
        "company": args.company,
        "tier": args.tier,
        "max_devices": args.max_devices,
        "duration_days": args.days,
        "stripe_subscription_id": args.stripe_subscription_id,
    }
    r = requests.post(f"{BASE_URL}/admin/generate-license", json=payload, headers=headers())
    print(r.status_code, r.json())


def license_info(args):
    payload = {"license_key": args.license_key}
    r = requests.post(f"{BASE_URL}/admin/license-info", json=payload, headers=headers())
    print(r.status_code, r.json())


def revoke_license(args):
    payload = {"license_key": args.license_key}
    r = requests.post(f"{BASE_URL}/admin/revoke", json=payload, headers=headers())
    print(r.status_code, r.json())


def list_licenses(args):
    # Simple list endpoint doesn't exist; use health as a fallback for now
    r = requests.get(f"{BASE_URL}/health")
    print(r.status_code, r.json())


def main():
    parser = argparse.ArgumentParser(description="Sentinel license server admin CLI")
    subparsers = parser.add_subparsers(dest="command")

    gen = subparsers.add_parser("generate", help="Generate a new license")
    gen.add_argument("--email", required=True)
    gen.add_argument("--name", default=None)
    gen.add_argument("--company", default=None)
    gen.add_argument("--tier", default="home")
    gen.add_argument("--max-devices", type=int, default=1)
    gen.add_argument("--days", type=int, default=None)
    gen.add_argument("--stripe-subscription-id", default=None)

    info = subparsers.add_parser("info", help="Get license info")
    info.add_argument("--license-key", required=True)

    revoke = subparsers.add_parser("revoke", help="Revoke a license")
    revoke.add_argument("--license-key", required=True)

    list_ = subparsers.add_parser("list", help="Check server status")

    args = parser.parse_args()

    if args.command == "generate":
        generate_license(args)
    elif args.command == "info":
        license_info(args)
    elif args.command == "revoke":
        revoke_license(args)
    elif args.command == "list":
        list_licenses(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
