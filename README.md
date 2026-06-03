# AutoEdge Licensing Server

Secure licensing and entitlement service for AutoEdge Trader strategy access.

The server receives Whop AutoEdge entitlement updates, stores customer/product/subscription/device state, exposes a manual admin UI, and gives Trader clients a clear license decision without exposing Whop secrets to Trader.

## Features

- HTTPS-ready deployment behind Caddy or another reverse proxy.
- SQLite database with durable tables for customers, products/strategies, subscriptions, entitlements, devices, license checks, webhook events, admin users/sessions, and audit log.
- Whop server-to-server endpoint secured with Standard Webhooks HMAC headers or an explicit bearer token fallback.
- Admin web UI:
  - search customers
  - inspect Whop IDs, email, license key suffix, subscriptions, entitlements, devices, check-ins, and audit events
  - manually grant, revoke, suspend, or expire strategy access
  - set expiry dates
  - block or unblock devices
  - manage product/strategy mappings
- Trader client endpoint:
  - activate/check by license key, email, customer id, or Whop user id
  - stores machine fingerprint hash and app version
  - returns licensed strategies, expiry, status, next check time, and grace period
- No Whop API key or webhook secret is needed by Trader clients.

## API

### Whop Entitlement Upsert

`POST /api/whop/entitlements`

Configure this URL in Whop:

```text
https://licenses.example.com/api/whop/entitlements
```

Whop documents webhooks as Standard Webhooks and recommends storing the dashboard webhook secret as `WHOP_WEBHOOK_SECRET`. The server verifies `webhook-id`, `webhook-timestamp`, and `webhook-signature` against the exact raw request body before trusting the payload.

The endpoint is idempotent by `webhook-id`. Duplicate deliveries return `{"status":"duplicate"}` after the first successful process.

### Trader License Check

`POST /api/trader/license/check`

Request:

```json
{
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "email": "customer@example.com",
  "customer_id": "optional-internal-customer-id",
  "whop_user_id": "optional-whop-user-id",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0"
}
```

At least one license identifier is required. `machine_fingerprint` is required.

Response:

```json
{
  "status": "active",
  "message": "License active.",
  "server_time": "2026-06-03T20:00:00Z",
  "customer": {
    "id": "customer-id",
    "email": "customer@example.com",
    "whop_user_id": "user-id",
    "license_key_last4": "ABCD"
  },
  "device": {
    "id": "device-id",
    "fingerprint_last8": "f00dbabe",
    "is_blocked": false
  },
  "licensed_strategies": [
    {
      "product_id": "product-id",
      "slug": "duo-runtime",
      "name": "Duo Runtime",
      "feature_id": "strategy.duo.runtime",
      "status": "active",
      "source": "whop",
      "expires_at": "2026-07-03T20:00:00Z"
    }
  ],
  "expires_at": "2026-07-03T20:00:00Z",
  "next_check_at": "2026-06-04T02:00:00Z",
  "next_check_seconds": 21600,
  "grace_period_seconds": 259200
}
```

Blocking statuses are explicit: `unknown_customer`, `unlicensed`, `expired`, `revoked`, `suspended`, `device_blocked`, `invalid_request`, and `rate_limited`.

Trader should allow strategy access only when `status == "active"` and the required `feature_id` is present in `licensed_strategies`.

## Local Development

```bash
cd /Users/andreas.geidnert/Dev/autoedge-licensing-server
cp .env.example .env
AUTOEDGE_ADMIN_COOKIE_SECRET="$(openssl rand -base64 48)" \
AUTOEDGE_WHOP_BEARER_TOKEN="local-test-token" \
AUTOEDGE_COOKIE_SECURE=false \
AUTOEDGE_SKIP_RUNTIME_VALIDATION=1 \
python3 -m autoedge_licensing.app
```

Open `http://127.0.0.1:8788/admin/login`.

Create the first admin:

```bash
AUTOEDGE_DATABASE_PATH=data/autoedge.db python3 scripts/create_admin.py admin
```

Seed initial strategy products:

```bash
AUTOEDGE_DATABASE_PATH=data/autoedge.db python3 scripts/seed_products.py \
  --duo-whop-product-id "replace-with-whop-product-id" \
  --duorc-whop-product-id "replace-with-whop-product-id"
```

Run tests:

```bash
python3 -m unittest discover -s tests
```

## Debian Deployment

Assumptions:

- Debian host with Python 3.11+.
- DNS for `licenses.example.com` points to the server.
- Caddy terminates HTTPS and proxies to the local Python service.

Install packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv caddy git
```

Create service user and directories:

```bash
sudo useradd --system --home /var/lib/autoedge-licensing --shell /usr/sbin/nologin autoedge
sudo mkdir -p /opt/autoedge-licensing /var/lib/autoedge-licensing
sudo chown -R autoedge:autoedge /var/lib/autoedge-licensing
```

Deploy code:

```bash
sudo git clone <repo-url> /opt/autoedge-licensing
sudo chown -R root:root /opt/autoedge-licensing
```

Create `/etc/autoedge-licensing.env`:

```dotenv
AUTOEDGE_DATABASE_PATH=/var/lib/autoedge-licensing/autoedge.db
AUTOEDGE_BIND_HOST=127.0.0.1
AUTOEDGE_BIND_PORT=8788
AUTOEDGE_PUBLIC_BASE_URL=https://licenses.example.com
AUTOEDGE_ADMIN_COOKIE_SECRET=replace-with-openssl-rand-base64-48
AUTOEDGE_COOKIE_SECURE=true
WHOP_WEBHOOK_SECRET=replace-with-whop-webhook-secret
AUTOEDGE_LICENSE_CHECK_INTERVAL_SECONDS=21600
AUTOEDGE_GRACE_PERIOD_SECONDS=259200
AUTOEDGE_RATE_LIMIT_PER_MINUTE=60
```

Protect the environment file:

```bash
sudo chown root:autoedge /etc/autoedge-licensing.env
sudo chmod 0640 /etc/autoedge-licensing.env
```

Install systemd unit:

```bash
sudo cp /opt/autoedge-licensing/systemd/autoedge-licensing.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now autoedge-licensing
sudo systemctl status autoedge-licensing
```

Install Caddy config:

```bash
sudo cp /opt/autoedge-licensing/deploy/Caddyfile /etc/caddy/Caddyfile
sudo sed -i 's/licenses.example.com/your-real-domain.example/g' /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Create admin and products as the service user:

```bash
sudo -u autoedge env $(sudo cat /etc/autoedge-licensing.env | xargs) \
  python3 /opt/autoedge-licensing/scripts/create_admin.py admin

sudo -u autoedge env $(sudo cat /etc/autoedge-licensing.env | xargs) \
  python3 /opt/autoedge-licensing/scripts/seed_products.py \
  --duo-whop-product-id "replace-with-whop-product-id" \
  --duorc-whop-product-id "replace-with-whop-product-id"
```

Configure Whop webhook:

- URL: `https://your-real-domain.example/api/whop/entitlements`
- Events: membership activation/update/deactivation and any payment/refund/dispute events you want reflected in access state.
- Secret: copy into `WHOP_WEBHOOK_SECRET`.

## Backups

Back up `/var/lib/autoedge-licensing/autoedge.db` and its WAL files, or stop the service briefly and copy the database file:

```bash
sudo systemctl stop autoedge-licensing
sudo cp /var/lib/autoedge-licensing/autoedge.db /var/backups/autoedge-$(date +%Y%m%d).db
sudo systemctl start autoedge-licensing
```

## Notes

- SQLite is appropriate for this initial licensing control plane. If license checks become high volume, the service layer is isolated enough to migrate to PostgreSQL.
- The admin UI intentionally stores only license key hashes and the last four characters of generated keys.
- Machine fingerprints are stored as SHA-256 hashes plus the last eight hash characters for support lookup.
