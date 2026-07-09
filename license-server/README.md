# Sentinel License Server

Self-hosted license server for the Sentinel Security Suite. Zero third-party licensing fees.

## Features

- RSA-signed JWT license keys
- Device fingerprinting with activation limits
- SQLite database (no external DB required)
- REST API for activation, validation, deactivation, and revocation
- Stripe webhook support for subscription lifecycle events
- Admin CLI for generating and managing licenses
- Rate limiting and audit logging hooks

## Setup

```bash
cd license-server
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

The server starts on `http://127.0.0.1:5000`.

## Environment Variables

- `LICENSE_DB` — SQLite database path (default: `licenses.db`)
- `ADMIN_TOKEN` — Bearer token for admin endpoints (default: `sentinel-admin-token`)
- `LICENSE_SERVER_URL` — Used by `admin.py` CLI (default: `http://127.0.0.1:5000`)

## Generate RSA Keys

Keys are generated automatically on first run. They are stored in:

- `private_key.pem`
- `public_key.pem`

## Admin CLI Examples

```bash
# Generate a 1-year Pro license
python admin.py generate --email user@example.com --tier pro --max-devices 3 --days 365

# Get license info
python admin.py info --license-key XXXX-XXXX-XXXX-XXXX

# Revoke a license
python admin.py revoke --license-key XXXX-XXXX-XXXX-XXXX
```

## Client Activation Flow

1. Distribute the `license_key` to the customer.
2. Customer's app calls `POST /activate` with `license_key`, `fingerprint`, `device_name`, and `platform`.
3. App calls `POST /validate` periodically with the same `license_key` and `fingerprint`.
4. To move a license to a new machine, call `POST /deactivate` first, then activate the new device.

## Testing

Start the server, then run:

```bash
python test_server.py
```

## API Endpoints

- `GET /health`
- `POST /admin/generate-license`
- `POST /admin/license-info`
- `POST /admin/revoke`
- `POST /admin/subscription-event`
- `POST /activate`
- `POST /validate`
- `POST /deactivate`
