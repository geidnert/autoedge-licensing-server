# AutoEdge Licensing Server

Secure licensing and entitlement service for AutoEdge Trader strategy access.

The server receives Whop AutoEdge entitlement updates, stores customer/product/subscription/device state, exposes a manual admin UI, and gives Trader clients a clear license decision without exposing Whop secrets to Trader.

## Features

- HTTPS-ready deployment behind Caddy or another reverse proxy.
- SQLite database with durable tables for customers, products/strategies, Whop packages, package grants, grant ledger, subscriptions, entitlements, devices, license checks, webhook events, admin users/sessions, and audit log.
- Whop server-to-server endpoint secured with Standard Webhooks HMAC headers or an explicit bearer token fallback.
- Admin web UI:
  - search customers
  - inspect Whop IDs, email, license key suffix, subscriptions, entitlements, devices, check-ins, and audit events
  - manually grant, revoke, suspend, or expire strategy access
  - set expiry dates
  - block or unblock devices
  - enforce and override per-customer device limits
  - manage Trader strategy products
  - map Whop plans/products to one or more strategies with day grants
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

The endpoint is idempotent by `webhook-id`. Duplicate deliveries return `{"status":"duplicate"}` after the first successful process. Paid/trial grants also use a grant ledger so repeated Whop events for the same payment, membership period, or trial do not add days twice.

### Whop Package Mappings

Products are internal Trader strategies, such as DUO or DUOrc. Whop Packages describe what Whop sells.

Configure packages in `/admin/packages`:

- Whop id: normally the Whop `plan_id`; `plan_id` takes precedence over `product_id`.
- Type: `plan`, `product`, or `unknown`.
- Default days: the days granted by the package.
- Non-license: marks a known Whop access pass as intentionally ignored.
- Grants: select one or more Trader strategies, with optional per-strategy days.

Old Vercel mappings like:

```text
plan_AsxYJxMdnQJqW=204,30:337,30:1175,30
```

become one Whop Package for `plan_AsxYJxMdnQJqW` with separate grant rows. Each grant chooses a Trader strategy and grants the configured days.

Lifecycle handling:

- Trialing events set access through `trial_ends_at` when Whop provides it.
- Paid/valid/renewed events add the package days onto `max(existing expiry, now)`, so paid days can start after the trial expiry.
- Duplicate paid events for the same payment id or membership period are suppressed by the grant ledger.
- `refund.created`, chargebacks, disputes, and `membership.went_invalid` revoke package entitlements.
- Expired, suspended, and revoked results are returned clearly to Trader so strategies can block access.

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
      "name": "DUO Runtime",
      "feature_id": "strategy.duo.runtime",
      "status": "active",
      "source": "whop",
      "expires_at": "2026-07-03T20:00:00Z"
    }
  ],
  "expires_at": "2026-07-03T20:00:00Z",
  "next_check_at": "2026-06-04T02:00:00Z",
  "next_check_seconds": 21600,
  "grace_period_seconds": 259200,
  "device_limit": {
    "active_devices": 1,
    "max_devices": 1,
    "device_is_counted": true
  }
}
```

Blocking statuses are explicit: `unknown_customer`, `unlicensed`, `expired`, `revoked`, `suspended`, `device_blocked`, `device_limit_exceeded`, `invalid_request`, and `rate_limited`.

Trader should allow strategy access only when `status == "active"` and the required `feature_id` is present in `licensed_strategies`.

`device_limit_exceeded` means the customer already has the maximum number of active licensed, non-blocked machines. Trader must block strategy access and must not offer package downloads for that machine. Admins can deauthorize a device, reset all devices for a customer, or set a customer-specific max device override in the customer detail page.

### Trader Release Manifest

`POST /api/trader/releases/manifest`

Request:

```json
{
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "email": "customer@example.com",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0",
  "channel": "stable",
  "platform": "windows-x64"
}
```

The same license identifiers as `/api/trader/license/check` are accepted. The response includes the normal license decision plus release metadata for active Trader app releases and active strategy releases only for strategies the customer is licensed to use.

Response:

```json
{
  "status": "active",
  "message": "Release manifest available.",
  "channel": "stable",
  "platform": "windows-x64",
  "releases": [
    {
      "id": "release-id",
      "scope": "strategy",
      "strategy": "DUO",
      "feature_id": "strategy.duo.runtime",
      "version": "1.2.0",
      "required": false,
      "update_available": true,
      "artifact": {
        "filename": "duo-1.2.0.zip",
        "size_bytes": 123456,
        "sha256": "hex-sha256",
        "signature": "optional-signature"
      },
      "release_notes": "Optional notes"
    }
  ],
  "license": {
    "status": "active"
  }
}
```

Trader should use the manifest only when `status == "active"`. Expired, revoked, suspended, blocked, or unknown customers receive an empty release list and the same blocking license status.

### Trader Release Download

`POST /api/trader/releases/download-token`

Request:

```json
{
  "release_id": "release-id-from-manifest",
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0"
}
```

The server checks the license again before issuing a short-lived download token. Strategy package downloads are allowed only when the license includes that strategy. Trader app downloads are allowed for any active license.

Response:

```json
{
  "status": "ok",
  "download_url": "https://licenses.example.com/api/trader/releases/download/token-value",
  "expires_at": "2026-06-04T12:00:00Z"
}
```

`GET /api/trader/releases/download/{token}` streams the artifact. Tokens are stored as hashes, expire quickly, and each download attempt is recorded in `release_downloads`.

Configure releases in `/admin/releases`. Artifact uploads are not handled by the web UI yet; copy package files under `AUTOEDGE_RELEASE_ARTIFACT_DIR` first, then register their relative path in the release form. If the file exists, the server calculates size and SHA-256 automatically.

## Local Development

```bash
cd /Users/andreas.geidnert/Dev/autoedge-licensing-server
cp .env.example .env
mkdir -p data/artifacts
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
AUTOEDGE_DATABASE_PATH=data/autoedge.db python3 scripts/seed_products.py
```

Then sign in to the admin UI and configure Whop Packages for the plan ids and day grants.

Run tests:

```bash
python3 -m unittest discover -s tests
```

## Debian Deployment

Assumptions:

- Debian host with Python 3.11+.
- DNS for the chosen HTTPS host points to the server.
- nginx or Caddy terminates HTTPS and proxies to the local Python service.

Install packages:

```bash
sudo apt update
sudo apt install -y python3 git nginx certbot python3-certbot-nginx
```

Create service user and directories:

```bash
sudo useradd --system --home /var/lib/autoedge-licensing --shell /usr/sbin/nologin autoedge
sudo mkdir -p /opt/autoedge-licensing /var/lib/autoedge-licensing/artifacts
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
AUTOEDGE_TRADER_MAX_DEVICES=1
AUTOEDGE_RATE_LIMIT_PER_MINUTE=60
AUTOEDGE_RELEASE_ARTIFACT_DIR=/var/lib/autoedge-licensing/artifacts
AUTOEDGE_RELEASE_DOWNLOAD_TOKEN_SECONDS=600
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

Install nginx routing:

```bash
sudo cp /opt/autoedge-licensing/deploy/nginx-autoedge-locations.conf \
  /etc/nginx/snippets/autoedge-licensing.conf
```

Include the snippet inside the HTTPS `server { ... }` block for the chosen hostname:

```nginx
include /etc/nginx/snippets/autoedge-licensing.conf;
```

Then validate and reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

If this is a fresh host and you prefer Caddy, use the included Caddyfile instead:

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
  python3 /opt/autoedge-licensing/scripts/seed_products.py
```

After seeding products, configure Whop Packages in the admin UI.

Configure Whop webhook:

- URL: `https://your-real-domain.example/api/whop/entitlements`
- Events: membership activation/update/deactivation and any payment/refund/dispute events you want reflected in access state.
- Secret: copy into `WHOP_WEBHOOK_SECRET`.

## Current Deployment

The current Debian deployment runs on `solidparts.se` behind nginx:

- Admin UI: `https://solidparts.se/admin/login`
- Admin password rotation: sign in, then use `Change password` in the top navigation.
- Trader endpoint: `https://solidparts.se/api/trader/license/check`
- Trader release manifest: `https://solidparts.se/api/trader/releases/manifest`
- Trader release downloads: `https://solidparts.se/api/trader/releases/download/{token}`
- Whop endpoint: `https://solidparts.se/api/whop/entitlements`
- Service unit: `autoedge-licensing.service`
- App directory: `/opt/autoedge-licensing`
- Database: `/var/lib/autoedge-licensing/autoedge.db`
- Release artifacts: `/var/lib/autoedge-licensing/artifacts`
- Environment file: `/etc/autoedge-licensing.env`

Production should use Whop Standard Webhooks with `WHOP_WEBHOOK_SECRET`. The bearer token fallback is intended only for local testing.

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
- `AUTOEDGE_TRADER_MAX_DEVICES` defaults to `1`. Blocked devices do not count. Devices are counted only after a successful active license check.
