"""Self-hosted Sentinel license server.

Endpoints:
- POST /admin/generate-license
- POST /activate
- POST /validate
- POST /deactivate
- POST /admin/revoke
- POST /admin/subscription-event
"""

import argparse
import os
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import jwt
from flask import Flask, jsonify, request
from flask_cors import CORS

from billing import (
    create_checkout_session,
    create_customer_portal_session,
    handle_webhook,
    is_configured,
)
from keys import ensure_keys, load_private_key, load_public_key
from models import (
    add_audit_event,
    add_customer,
    add_device,
    add_license,
    add_subscription,
    deactivate_device,
    get_customer,
    get_device,
    get_devices_for_license,
    get_db,
    get_license,
    get_subscription,
    init_db,
    revoke_license,
    update_device_last_seen,
    update_subscription_status,
)

app = Flask(__name__)
CORS(app)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "sentinel-admin-token")

# === Rate limiting (in-memory) ===
_rate_limit_buckets = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX = 20  # requests per window per IP


def _prune_bucket(bucket, now):
    cutoff = now - RATE_LIMIT_WINDOW
    while bucket and bucket[0] < cutoff:
        bucket.pop(0)


def rate_limit(func):
    """Decorator that limits requests per IP per endpoint."""
    def wrapper(*args, **kwargs):
        ip = get_client_ip()
        key = f"{ip}:{func.__name__}"
        now = time.time()
        bucket = _rate_limit_buckets[key]
        _prune_bucket(bucket, now)
        if len(bucket) >= RATE_LIMIT_MAX:
            return jsonify({"success": False, "error": "Rate limit exceeded"}), 429
        bucket.append(now)
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def require_json(func):
    """Decorator that ensures request is JSON and not empty."""
    def wrapper(*args, **kwargs):
        if not request.is_json:
            return jsonify({"success": False, "error": "JSON body required"}), 400
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


# === Helpers ===

def generate_license_key():
    """Generate a random, readable license key."""
    parts = [secrets.token_hex(4).upper() for _ in range(4)]
    return "-".join(parts)


def sign_license(license_data):
    """Sign license data as a JWT using the RSA private key."""
    private_key = load_private_key()
    return jwt.encode(license_data, private_key, algorithm="RS256")


def verify_license(token):
    """Verify a JWT license token using the RSA public key."""
    public_key = load_public_key()
    try:
        return jwt.decode(token, public_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def require_admin_token():
    """Check the Authorization header for the admin token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    return auth.split(" ", 1)[1] == ADMIN_TOKEN


def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"


def is_expired(license_row):
    if license_row["status"] != "active":
        return True
    if license_row["expires_at"]:
        expires = datetime.fromisoformat(license_row["expires_at"])
        if expires < datetime.now(timezone.utc):
            return True
    return False


# === Endpoints ===

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/admin/generate-license", methods=["POST"])
def generate_license():
    if not require_admin_token():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json or {}
    email = data.get("email")
    tier = data.get("tier", "home")
    max_devices = data.get("max_devices", 1)
    duration_days = data.get("duration_days")
    stripe_subscription_id = data.get("stripe_subscription_id")

    if not email:
        return jsonify({"success": False, "error": "Email is required"}), 400

    # Find or create customer
    customer = get_customer(email=email)
    if not customer:
        customer_id = add_customer(email, data.get("name"), data.get("company"))
    else:
        customer_id = customer["id"]

    # Create subscription record
    started_at = datetime.now(timezone.utc)
    expires_at = None
    if duration_days:
        expires_at = (started_at + timedelta(days=duration_days)).isoformat()

    subscription_id = add_subscription(
        customer_id=customer_id,
        tier=tier,
        started_at=started_at.isoformat(),
        expires_at=expires_at,
        stripe_subscription_id=stripe_subscription_id,
    )

    # Generate license key
    license_key = generate_license_key()
    license_id = add_license(
        license_key=license_key,
        tier=tier,
        max_devices=max_devices,
        customer_id=customer_id,
        subscription_id=subscription_id,
        expires_at=expires_at,
    )

    # Build signed JWT
    license_data = {
        "license_key": license_key,
        "customer_id": customer_id,
        "subscription_id": subscription_id,
        "tier": tier,
        "max_devices": max_devices,
        "exp": datetime.fromisoformat(expires_at) if expires_at else None,
        "iat": started_at,
    }
    if license_data["exp"] is None:
        del license_data["exp"]

    signed_key = sign_license(license_data)

    add_audit_event(license_id, "generated", details=f"Tier {tier}, max_devices {max_devices}", ip_address=get_client_ip())

    return jsonify({
        "success": True,
        "license_key": license_key,
        "signed_key": signed_key,
        "tier": tier,
        "max_devices": max_devices,
        "expires_at": expires_at,
    })


@app.route("/activate", methods=["POST"])
def activate():
    data = request.json or {}
    license_key = data.get("license_key")
    fingerprint = data.get("fingerprint")
    device_name = data.get("device_name")
    platform = data.get("platform")

    if not license_key or not fingerprint:
        return jsonify({"success": False, "error": "license_key and fingerprint are required"}), 400

    license_row = get_license(license_key)
    if not license_row:
        return jsonify({"success": False, "error": "Invalid license key"}), 403

    if is_expired(license_row):
        return jsonify({"success": False, "error": "License expired or revoked"}), 403

    # Check if device is already activated
    device = get_device(license_row["id"], fingerprint)
    active_devices = get_devices_for_license(license_row["id"])

    if device:
        update_device_last_seen(device["id"])
        add_audit_event(license_row["id"], "activation_renewed", details=f"Device {fingerprint}", ip_address=get_client_ip())
        return jsonify({
            "success": True,
            "message": "Device already activated",
            "license": {
                "license_key": license_row["license_key"],
                "tier": license_row["tier"],
                "max_devices": license_row["max_devices"],
                "active_devices": len(active_devices),
            },
        })

    if len(active_devices) >= license_row["max_devices"]:
        return jsonify({"success": False, "error": "Maximum device limit reached"}), 403

    add_device(license_row["id"], fingerprint, device_name, platform)
    add_audit_event(license_row["id"], "activated", details=f"Device {fingerprint}", ip_address=get_client_ip())

    return jsonify({
        "success": True,
        "message": "Device activated",
        "license": {
            "license_key": license_row["license_key"],
            "tier": license_row["tier"],
            "max_devices": license_row["max_devices"],
            "active_devices": len(active_devices) + 1,
        },
    })


@app.route("/validate", methods=["POST"])
def validate():
    data = request.json or {}
    license_key = data.get("license_key")
    fingerprint = data.get("fingerprint")

    if not license_key or not fingerprint:
        return jsonify({"success": False, "error": "license_key and fingerprint are required"}), 400

    license_row = get_license(license_key)
    if not license_row:
        return jsonify({"success": False, "error": "Invalid license key"}), 403

    if is_expired(license_row):
        add_audit_event(license_row["id"], "validation_failed", details="License expired or revoked", ip_address=get_client_ip())
        return jsonify({"success": False, "error": "License expired or revoked"}), 403

    device = get_device(license_row["id"], fingerprint)
    if not device or not device["active"]:
        return jsonify({"success": False, "error": "Device not activated"}), 403

    update_device_last_seen(device["id"])
    add_audit_event(license_row["id"], "validated", details=f"Device {fingerprint}", ip_address=get_client_ip())

    return jsonify({
        "success": True,
        "valid": True,
        "license": {
            "license_key": license_row["license_key"],
            "tier": license_row["tier"],
            "max_devices": license_row["max_devices"],
            "active_devices": len(get_devices_for_license(license_row["id"])),
        },
    })


@app.route("/deactivate", methods=["POST"])
def deactivate():
    data = request.json or {}
    license_key = data.get("license_key")
    fingerprint = data.get("fingerprint")

    if not license_key or not fingerprint:
        return jsonify({"success": False, "error": "license_key and fingerprint are required"}), 400

    license_row = get_license(license_key)
    if not license_row:
        return jsonify({"success": False, "error": "Invalid license key"}), 403

    device = get_device(license_row["id"], fingerprint)
    if not device:
        return jsonify({"success": False, "error": "Device not found"}), 404

    deactivate_device(device["id"])
    add_audit_event(license_row["id"], "deactivated", details=f"Device {fingerprint}", ip_address=get_client_ip())

    return jsonify({"success": True, "message": "Device deactivated"})


@app.route("/admin/revoke", methods=["POST"])
@rate_limit
@require_json
def admin_revoke():
    if not require_admin_token():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json or {}
    license_key = data.get("license_key")
    if not license_key:
        return jsonify({"success": False, "error": "license_key is required"}), 400

    license_row = get_license(license_key)
    if not license_row:
        return jsonify({"success": False, "error": "License not found"}), 404

    revoke_license(license_row["id"])
    add_audit_event(license_row["id"], "revoked", details="License revoked by admin", ip_address=get_client_ip())

    return jsonify({"success": True, "message": "License revoked"})


@app.route("/billing/checkout", methods=["POST"])
@rate_limit
@require_json
def billing_checkout():
    """Create a Stripe Checkout session for a subscription."""
    data = request.json or {}
    email = data.get("email")
    tier = data.get("tier", "home")
    if not email:
        return jsonify({"success": False, "error": "email is required"}), 400
    result = create_checkout_session(email, tier)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/billing/customer-portal", methods=["POST"])
@rate_limit
@require_json
def billing_customer_portal():
    """Create a Stripe Customer Portal session."""
    data = request.json or {}
    stripe_customer_id = data.get("stripe_customer_id")
    if not stripe_customer_id:
        return jsonify({"success": False, "error": "stripe_customer_id is required"}), 400
    result = create_customer_portal_session(stripe_customer_id)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/stripe/webhook", methods=["POST"])
@rate_limit
def stripe_webhook():
    """Handle Stripe webhook events for subscription lifecycle."""
    payload = request.get_data(as_text=True)
    signature = request.headers.get("Stripe-Signature", "")
    result = handle_webhook(payload, signature)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code


@app.route("/admin/subscription-event", methods=["POST"])
@rate_limit
@require_json
def subscription_event():
    """Handle Stripe webhook events for subscription lifecycle."""
    if not require_admin_token():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json or {}
    event_type = data.get("event_type")
    stripe_subscription_id = data.get("stripe_subscription_id")

    if not event_type or not stripe_subscription_id:
        return jsonify({"success": False, "error": "event_type and stripe_subscription_id are required"}), 400

    subscription = get_subscription_by_stripe_id(stripe_subscription_id)
    if not subscription:
        return jsonify({"success": False, "error": "Subscription not found"}), 404

    new_status = "active"
    if event_type in ["customer.subscription.deleted", "customer.subscription.paused"]:
        new_status = "inactive"
    elif event_type == "customer.subscription.updated":
        new_status = data.get("status", "active")

    update_subscription_status(subscription["id"], new_status)

    # Update linked licenses
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE licenses SET status = ? WHERE subscription_id = ?",
            ("active" if new_status == "active" else "revoked", subscription["id"]),
        )
        conn.commit()

    add_audit_event(None, "subscription_event", details=f"{event_type} for {stripe_subscription_id}", ip_address=get_client_ip())

    return jsonify({"success": True, "status": new_status})


def get_subscription_by_stripe_id(stripe_subscription_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM subscriptions WHERE stripe_subscription_id = ?",
            (stripe_subscription_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None


@app.route("/admin/license-info", methods=["POST"])
@rate_limit
@require_json
def admin_license_info():
    if not require_admin_token():
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    data = request.json or {}
    license_key = data.get("license_key")
    if not license_key:
        return jsonify({"success": False, "error": "license_key is required"}), 400

    license_row = get_license(license_key)
    if not license_row:
        return jsonify({"success": False, "error": "License not found"}), 404

    devices = get_devices_for_license(license_row["id"])
    customer = get_customer(license_row["customer_id"])
    subscription = get_subscription(license_row["subscription_id"])

    return jsonify({
        "success": True,
        "license": license_row,
        "customer": customer,
        "subscription": subscription,
        "devices": devices,
    })


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    args = parser.parse_args()
    ensure_keys()
    init_db()
    app.run(host=args.host, port=args.port, debug=False)
