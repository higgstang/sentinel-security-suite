"""Tests for Stripe billing endpoints."""

import os
import requests

SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "http://127.0.0.1:5000")


def test_billing_checkout_without_config():
    """Checkout should fail gracefully if Stripe is not configured."""
    payload = {"email": "test@example.com", "tier": "home"}
    r = requests.post(f"{SERVER_URL}/billing/checkout", json=payload)
    assert r.status_code == 400
    data = r.json()
    assert not data.get("success")
    assert "Stripe is not configured" in data.get("error", "")


def test_billing_customer_portal_without_config():
    """Customer portal should fail gracefully if Stripe is not configured."""
    payload = {"stripe_customer_id": "cus_123"}
    r = requests.post(f"{SERVER_URL}/billing/customer-portal", json=payload)
    assert r.status_code == 400
    data = r.json()
    assert not data.get("success")


def test_stripe_webhook_without_config():
    """Webhook should fail gracefully if webhook secret is not configured."""
    r = requests.post(f"{SERVER_URL}/stripe/webhook", data="{}", headers={"Stripe-Signature": "test"})
    assert r.status_code == 400
    data = r.json()
    assert not data.get("success")


def test_billing_checkout_missing_email():
    """Checkout should require email."""
    r = requests.post(f"{SERVER_URL}/billing/checkout", json={"tier": "home"})
    assert r.status_code == 400
    data = r.json()
    assert "email is required" in data.get("error", "")


def test_customer_portal_missing_id():
    """Customer portal should require stripe_customer_id."""
    r = requests.post(f"{SERVER_URL}/billing/customer-portal", json={})
    assert r.status_code == 400
    data = r.json()
    assert "stripe_customer_id is required" in data.get("error", "")


if __name__ == "__main__":
    test_billing_checkout_without_config()
    test_billing_customer_portal_without_config()
    test_stripe_webhook_without_config()
    test_billing_checkout_missing_email()
    test_customer_portal_missing_id()
    print("All billing tests passed.")
