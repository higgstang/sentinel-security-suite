"""Stripe billing integration for Sentinel license server.

Environment variables:
- STRIPE_SECRET_KEY
- STRIPE_WEBHOOK_SECRET
- STRIPE_PRICE_HOME, STRIPE_PRICE_BUSINESS, STRIPE_PRICE_ENTERPRISE
- STRIPE_SUCCESS_URL, STRIPE_CANCEL_URL
"""

import os

import stripe

from models import (
    add_customer,
    add_license,
    add_subscription,
    get_customer,
    update_subscription_status,
)

stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

PRICE_MAP = {
    "home": os.environ.get("STRIPE_PRICE_HOME", ""),
    "business": os.environ.get("STRIPE_PRICE_BUSINESS", ""),
    "enterprise": os.environ.get("STRIPE_PRICE_ENTERPRISE", ""),
}

TIER_DEVICES = {"home": 1, "business": 5, "enterprise": 50}

SUCCESS_URL = os.environ.get("STRIPE_SUCCESS_URL", "http://localhost:3000/success?session_id={CHECKOUT_SESSION_ID}")
CANCEL_URL = os.environ.get("STRIPE_CANCEL_URL", "http://localhost:3000/cancel")


def is_configured():
    return bool(stripe.api_key)


def create_checkout_session(email, tier, customer_id=None):
    """Create a Stripe Checkout session for a new subscription."""
    if not is_configured():
        return {"success": False, "error": "Stripe is not configured"}

    price_id = PRICE_MAP.get(tier)
    if not price_id:
        return {"success": False, "error": f"No price configured for tier {tier}"}

    try:
        customer = None
        if customer_id:
            customer = get_customer(customer_id)
        if not customer:
            customer_id = add_customer(email)

        metadata = {
            "customer_id": str(customer_id),
            "tier": tier,
        }

        session = stripe.checkout.Session.create(
            customer_email=email if not customer else None,
            customer=customer["email"] if customer else None,
            line_items=[{"price": price_id, "quantity": 1}],
            mode="subscription",
            success_url=SUCCESS_URL,
            cancel_url=CANCEL_URL,
            metadata=metadata,
            subscription_data={"metadata": metadata},
        )
        return {"success": True, "session_id": session.id, "url": session.url}
    except stripe.error.StripeError as e:
        return {"success": False, "error": str(e)}


def create_customer_portal_session(stripe_customer_id):
    """Create a Stripe Customer Portal session."""
    if not is_configured():
        return {"success": False, "error": "Stripe is not configured"}
    try:
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url="http://localhost:3000/dashboard",
        )
        return {"success": True, "url": session.url}
    except stripe.error.StripeError as e:
        return {"success": False, "error": str(e)}


def handle_webhook(payload, signature):
    """Verify and process a Stripe webhook event."""
    if not WEBHOOK_SECRET:
        return {"success": False, "error": "Webhook secret not configured"}

    try:
        event = stripe.Webhook.construct_event(payload, signature, WEBHOOK_SECRET)
    except ValueError as e:
        return {"success": False, "error": f"Invalid payload: {e}"}
    except stripe.error.SignatureVerificationError as e:
        return {"success": False, "error": f"Invalid signature: {e}"}

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        _handle_checkout_completed(data)
    elif event_type == "customer.subscription.created":
        _handle_subscription_created(data)
    elif event_type == "customer.subscription.updated":
        _handle_subscription_updated(data)
    elif event_type == "customer.subscription.deleted":
        _handle_subscription_deleted(data)

    return {"success": True, "event_type": event_type}


def _handle_checkout_completed(session):
    """When checkout completes, create a license and subscription record."""
    subscription_id = session.get("subscription")
    if not subscription_id:
        return

    # Fetch full subscription to get metadata and status
    subscription = stripe.Subscription.retrieve(subscription_id)
    metadata = subscription.get("metadata", {})
    tier = metadata.get("tier", "home")
    customer_id = int(metadata.get("customer_id", 0))

    if not customer_id:
        return

    stripe_customer_id = subscription.get("customer")
    status = subscription.get("status", "active")
    started_at = subscription.get("start_date")
    started_iso = None
    if started_at:
        from datetime import datetime, timezone
        started_iso = datetime.fromtimestamp(started_at, tz=timezone.utc).isoformat()

    expires_at = None
    current_period_end = subscription.get("current_period_end")
    if current_period_end:
        from datetime import datetime, timezone
        expires_at = datetime.fromtimestamp(current_period_end, tz=timezone.utc).isoformat()

    subscription_db_id = add_subscription(
        customer_id=customer_id,
        tier=tier,
        started_at=started_iso,
        expires_at=expires_at,
        stripe_subscription_id=subscription_id,
    )

    license_key = _generate_key()
    add_license(
        license_key=license_key,
        tier=tier,
        max_devices=TIER_DEVICES.get(tier, 1),
        customer_id=customer_id,
        subscription_id=subscription_db_id,
        expires_at=expires_at,
    )

    # Update customer with stripe customer id (not tracked in schema; could be added)
    return {"success": True, "license_key": license_key}


def _handle_subscription_created(subscription):
    """Called when Stripe creates a subscription."""
    pass


def _handle_subscription_updated(subscription):
    """Update subscription status and expiration when Stripe updates it."""
    stripe_subscription_id = subscription.get("id")
    status = subscription.get("status", "active")
    new_status = "active" if status in ["active", "trialing"] else "inactive"
    update_subscription_status_by_stripe_id(stripe_subscription_id, new_status)


def _handle_subscription_deleted(subscription):
    """Mark subscription and license as revoked when deleted."""
    stripe_subscription_id = subscription.get("id")
    update_subscription_status_by_stripe_id(stripe_subscription_id, "inactive")


def update_subscription_status_by_stripe_id(stripe_subscription_id, status):
    from models import get_db
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE subscriptions SET status = ? WHERE stripe_subscription_id = ?",
            (status, stripe_subscription_id),
        )
        cur.execute(
            """
            UPDATE licenses SET status = ?
            WHERE subscription_id IN (
                SELECT id FROM subscriptions WHERE stripe_subscription_id = ?
            )
            """,
            ("active" if status == "active" else "revoked", stripe_subscription_id),
        )
        conn.commit()


def _generate_key():
    import secrets
    parts = [secrets.token_hex(4).upper() for _ in range(4)]
    return "-".join(parts)
