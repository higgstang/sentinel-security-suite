"""Database models and schema for the Sentinel license server.

Uses SQLite to avoid third-party database hosting fees.
"""

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DATABASE = os.environ.get("LICENSE_DB", "licenses.db")


@contextmanager
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """Create the license server tables if they don't exist."""
    with get_db() as conn:
        cur = conn.cursor()

        # Customers table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                name TEXT,
                company TEXT,
                created_at TEXT NOT NULL
            )
            """
        )

        # Subscriptions table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id INTEGER NOT NULL,
                stripe_subscription_id TEXT UNIQUE,
                tier TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                started_at TEXT NOT NULL,
                expires_at TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            )
            """
        )

        # Licenses table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_key TEXT UNIQUE NOT NULL,
                customer_id INTEGER,
                subscription_id INTEGER,
                tier TEXT NOT NULL,
                max_devices INTEGER NOT NULL DEFAULT 1,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (customer_id) REFERENCES customers(id),
                FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
            )
            """
        )

        # Devices table
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                device_name TEXT,
                platform TEXT,
                activated_at TEXT NOT NULL,
                last_seen_at TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (license_id) REFERENCES licenses(id),
                UNIQUE(license_id, fingerprint)
            )
            """
        )

        # Audit log for activations / validations / revocations
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id INTEGER,
                event_type TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                created_at TEXT NOT NULL
            )
            """
        )

        # Indexes for common lookups
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_licenses_key ON licenses(license_key)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_devices_fingerprint ON devices(license_id, fingerprint)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe ON subscriptions(stripe_subscription_id)"
        )

        conn.commit()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def add_customer(email, name=None, company=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO customers (email, name, company, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (email, name, company, now_iso()),
        )
        conn.commit()
        return cur.lastrowid


def get_customer(customer_id=None, email=None):
    with get_db() as conn:
        cur = conn.cursor()
        if customer_id:
            cur.execute("SELECT * FROM customers WHERE id = ?", (customer_id,))
        elif email:
            cur.execute("SELECT * FROM customers WHERE email = ?", (email,))
        else:
            return None
        row = cur.fetchone()
        return dict(row) if row else None


def add_subscription(customer_id, tier, started_at, expires_at=None, stripe_subscription_id=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO subscriptions (customer_id, tier, status, started_at, expires_at, stripe_subscription_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (customer_id, tier, "active", started_at, expires_at, stripe_subscription_id),
        )
        conn.commit()
        return cur.lastrowid


def get_subscription(subscription_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM subscriptions WHERE id = ?", (subscription_id,))
        row = cur.fetchone()
        return dict(row) if row else None


def update_subscription_status(subscription_id, status):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE subscriptions SET status = ? WHERE id = ?",
            (status, subscription_id),
        )
        conn.commit()


def add_license(license_key, tier, max_devices=1, customer_id=None, subscription_id=None, expires_at=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO licenses (license_key, customer_id, subscription_id, tier, max_devices, status, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (license_key, customer_id, subscription_id, tier, max_devices, "active", now_iso(), expires_at),
        )
        conn.commit()
        return cur.lastrowid


def get_license(license_key):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM licenses WHERE license_key = ?", (license_key,))
        row = cur.fetchone()
        return dict(row) if row else None


def revoke_license(license_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE licenses SET status = 'revoked', revoked_at = ? WHERE id = ?",
            (now_iso(), license_id),
        )
        cur.execute(
            "UPDATE devices SET active = 0 WHERE license_id = ?",
            (license_id,),
        )
        conn.commit()


def get_devices_for_license(license_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM devices WHERE license_id = ? AND active = 1",
            (license_id,),
        )
        return [dict(row) for row in cur.fetchall()]


def get_device(license_id, fingerprint):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM devices WHERE license_id = ? AND fingerprint = ?",
            (license_id, fingerprint),
        )
        row = cur.fetchone()
        return dict(row) if row else None


def add_device(license_id, fingerprint, device_name=None, platform=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO devices (license_id, fingerprint, device_name, platform, activated_at, last_seen_at, active)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            """,
            (license_id, fingerprint, device_name, platform, now_iso(), now_iso()),
        )
        conn.commit()
        return cur.lastrowid


def update_device_last_seen(device_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE devices SET last_seen_at = ? WHERE id = ?",
            (now_iso(), device_id),
        )
        conn.commit()


def deactivate_device(device_id):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE devices SET active = 0 WHERE id = ?",
            (device_id,),
        )
        conn.commit()


def add_audit_event(license_id, event_type, details=None, ip_address=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_log (license_id, event_type, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (license_id, event_type, details, ip_address, now_iso()),
        )
        conn.commit()
