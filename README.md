# AutoEdge Licensing Server

Secure licensing and entitlement service for AutoEdge Trader strategy access.

The server receives Whop AutoEdge entitlement updates, stores customer/product/subscription/device state, exposes a manual admin UI, and gives Trader clients a clear license decision without exposing Whop secrets to Trader.

## Features

- HTTPS-ready deployment behind Caddy or another reverse proxy.
- SQLite database with durable tables for customers, products/strategies/extensions, Whop packages, package grants, grant ledger, subscriptions, entitlements, devices, license checks, webhook events, admin users/sessions, and audit log.
- Whop server-to-server endpoint secured with Standard Webhooks HMAC headers or an explicit bearer token fallback.
- Admin web UI:
  - search customers
  - inspect Whop IDs, email, license key suffix, subscriptions, entitlements, devices, check-ins, and audit events
  - manually grant, revoke, suspend, or expire strategy access
  - set expiry dates
  - set manual strategy access to Lifetime with no expiry
  - remove individual entitlement rows from a customer
  - block or unblock devices
  - enforce and override per-customer device limits
  - manage Trader strategy and extension products
  - map Whop plans/products to one or more licensed products with day grants
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

Products are internal licensed Trader capabilities, such as DUO, DUOrc, or optional Trader Desktop extensions. Whop Packages describe what Whop sells.

Configure packages in `/admin/packages`:

- Whop id: normally the Whop `plan_id`; `plan_id` takes precedence over `product_id`.
- Type: `plan`, `product`, or `unknown`.
- Default days: the days granted by the package.
- Non-license: marks a known Whop access pass as intentionally ignored.
- Grants: select one or more licensed products, with optional per-product days.

Old Vercel mappings like:

```text
plan_AsxYJxMdnQJqW=204,30:337,30:1175,30
```

become one Whop Package for `plan_AsxYJxMdnQJqW` with separate grant rows. Each grant chooses a licensed product and grants the configured days.

Built-in seed products include the optional Trader Desktop extension:

- Display name: `Discord Notifier`
- Product slug/package id: `discord-notifier`
- Feature id: `trader.notifications.discord`
- Release type: `extension_package`

A customer must have an active grant for `trader.notifications.discord` to see or download Discord Notifier extension releases.

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

Trader should allow strategy or extension access only when `status == "active"` and the required `feature_id` is present in `licensed_strategies`. The field name is legacy; it can contain any active Trader-enabled licensed product, including optional extensions such as `trader.notifications.discord`.

Manual Lifetime grants and other no-expiry entitlements are represented as `expires_at: null` on the affected `licensed_strategies` entries. The top-level `expires_at` is `null` only when all licensed strategies in the response have no expiry.

`device_limit_exceeded` means the customer already has the maximum number of active licensed, non-blocked machines. Trader must block strategy access and must not offer package downloads for that machine. If an admin lowers a customer limit below the current active device count, only the earliest active device(s) up to the new limit remain allowed; later devices are denied until the admin deauthorizes/resets devices or raises the limit. Admins can deauthorize a device, reset all devices for a customer, or set a customer-specific max device override in the customer detail page.

### NinjaTrader 8 License Check

`POST /api/nt8/license/check`

NT8 uses the same customers, Whop packages, manual grants, expiry dates, devices, device limits, and audit log as Trader Desktop. Products include explicit NT8 fields in the admin UI:

- `NT8 key`: the strategy key returned to NT8, for example `DUO` or `DUOrc`
- `Trader`: whether Trader Desktop should receive this product in license responses
- `NT8`: whether NinjaTrader 8 should receive this product in license responses

Request:

```json
{
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "email": "customer@example.com",
  "customer_id": "optional-internal-customer-id",
  "whop_user_id": "optional-whop-user-id",
  "machine_fingerprint": "stable-nt8-machine-fingerprint",
  "nt8_version": "8.1.5",
  "strategy": "DUO"
}
```

At least one license identifier is required. `machine_fingerprint` is required. `strategy` is optional; when supplied, the server returns `unlicensed_strategy` if the customer is active but that exact NT8 strategy key is not licensed.

Response:

```json
{
  "status": "active",
  "licensed": true,
  "message": "License active.",
  "server_time": "2026-06-03T20:00:00Z",
  "customer": {
    "id": "customer-id",
    "email": "customer@example.com",
    "license_key_last4": "ABCD"
  },
  "device": {
    "id": "device-id",
    "fingerprint_last8": "f00dbabe",
    "is_blocked": false,
    "client_type": "nt8"
  },
  "strategies": [
    {
      "key": "DUO",
      "name": "DUO Runtime",
      "product_id": "product-id",
      "status": "active",
      "source": "whop",
      "expires_at": "2026-07-03T20:00:00Z"
    }
  ],
  "strategy_keys": ["DUO"],
  "requested_strategy": "DUO",
  "expires_at": "2026-07-03T20:00:00Z",
  "next_check_seconds": 21600,
  "grace_period_seconds": 259200,
  "lease": {
    "token": "server-signed-opaque-token",
    "issued_at": "2026-06-03T20:00:00Z",
    "expires_at": "2026-06-06T20:00:00Z"
  }
}
```

Blocking statuses are explicit: `unknown_customer`, `unlicensed`, `unlicensed_strategy`, `expired`, `revoked`, `suspended`, `device_blocked`, `device_limit_exceeded`, `invalid_request`, and `rate_limited`. NT8 should allow strategy use only when `licensed == true` and the required strategy key is present in `strategy_keys`.

Manual Lifetime grants and other no-expiry entitlements are represented as `expires_at: null` on the affected `strategies` entries. The top-level NT8 `expires_at` is `null` only when all licensed strategies in the response have no expiry.

The `lease.token` is HMAC-signed by the server and is useful as an opaque cache marker and for future server-side validation. It is not a public-key offline-verifiable token; do not embed the server lease secret in NT8. If true offline signature verification becomes required, add an asymmetric signing dependency and ship only a public key in NT8.

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
  "platform": "macos-arm64",
  "include_types": ["strategy_package", "extension_package", "trader_desktop"],
  "installed_packages": [
    { "package_id": "duo-runtime", "version": "1.1.0" },
    { "package_id": "duorc-runtime", "version": "1.0.0" }
  ]
}
```

The same license identifiers as `/api/trader/license/check` are accepted. The response includes the normal license decision plus:

- `releases`: product-bound package releases only for features the customer is licensed and targeted to use.
- `app_update`: the Trader Desktop target release for the customer when it differs from `app_version`.

If `include_types` is omitted, both `strategy_package` and `trader_desktop` are included for backward compatibility. Future clients should request `extension_package` when they can install optional Trader extensions such as Discord Notifier.

`installed_packages` is optional and lets the server compare each package against the version installed locally. If omitted, older clients still receive the same compatible release rows.

Release targeting is fully server-side. The client only sees releases it is allowed to see. Admins can target releases by channel, customer id, email, full license key, customer tags/roles, deterministic rollout percent, or disable the release audience entirely.

Response:

```json
{
  "status": "active",
  "message": "Release manifest available.",
  "channel": "stable",
  "platform": "macos-arm64",
  "releases": [
    {
      "id": "release-id",
      "release_id": "release-id",
      "scope": "strategy",
      "release_type": "strategy_package",
      "package_id": "duo-runtime",
      "display_name": "DUO",
      "strategy": "DUO",
      "product_id": "product-id",
      "feature_id": "strategy.duo.runtime",
      "required_features": ["strategy.duo.runtime"],
      "version": "1.2.0",
      "required": false,
      "license_status": "active",
      "license_source": "whop",
      "expires_at": "2026-07-03T20:00:00Z",
      "current_version": "1.1.0",
      "target_version": "1.2.0",
      "action": "update",
      "update_available": true,
      "artifact": {
        "path": "duo-1.2.0.zip",
        "filename": "duo-1.2.0.zip",
        "size_bytes": 123456,
        "sha256": "hex-sha256",
        "signature": "optional-signature",
        "signature_key_id": "optional-key-id"
      },
      "release_notes": "Optional notes",
      "rollback_reason": null
    }
  ],
  "app_update": {
    "product_id": "trader-desktop",
    "release_type": "trader_desktop",
    "current_version": "0.1.0",
    "available_version": "0.1.1",
    "target_version": "0.1.1",
    "action": "update",
    "update_available": true,
    "release_id": "release-id",
    "channel": "stable",
    "platform": "macos-arm64",
    "min_supported_version": "0.1.0",
    "required": false,
    "artifact": {
      "path": "trader/Trader-Setup-0.1.1-macos-arm64.zip",
      "filename": "Trader-Setup-0.1.1-macos-arm64.zip",
      "size_bytes": 123456,
      "sha256": "hex-sha256",
      "signature": "optional-signature",
      "signature_key_id": "optional-key-id"
    },
    "release_notes": "Optional notes",
    "rollback_reason": null
  },
  "license": {
    "status": "active"
  }
}
```

Extension package releases use the same `releases` array with `release_type: "extension_package"` and `scope: "extension"`. Discord Notifier release rows use `package_id: "discord-notifier"`, `display_name: "Discord Notifier"`, and `required_features: ["trader.notifications.discord"]`.

Trader should use the manifest only when `status == "active"`. Expired, revoked, suspended, blocked, device-limit-exceeded, or unknown customers receive an empty release list, `app_update: null`, and the same blocking license status.

`action` is one of:

- `update`: target version is newer than the installed/current version.
- `rollback`: target version is lower and the server has explicitly directed rollback by marking the release required or setting a rollback reason.
- `current`: target version equals the installed/current version.

Rollback is server-directed. Trader Desktop and strategies must not infer that a newer local version is valid if the server returns a lower `target_version` with `action: "rollback"`.

### Trader Release Download

`POST /api/trader/releases/download-token`

Request:

```json
{
  "release_id": "release-id-from-manifest",
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0",
  "channel": "stable",
  "platform": "macos-arm64",
  "installed_packages": [
    { "package_id": "duo-runtime", "version": "1.1.0" }
  ]
}
```

The server checks the license, device limit, platform, and release targeting again before issuing a short-lived download token. Product-bound package downloads, including `strategy_package` and `extension_package`, are allowed only when the license includes the required product feature. Trader Desktop downloads are allowed for active licenses only when the customer is targeted for that app release. A customer cannot download a release merely by knowing its `release_id`.

Response:

```json
{
  "status": "ok",
  "download_url": "https://licenses.example.com/api/trader/releases/download/token-value",
  "expires_at": "2026-06-04T12:00:00Z"
}
```

`GET /api/trader/releases/download/{token}` streams the artifact. Tokens are stored as hashes, expire quickly, and each download attempt is recorded in `release_downloads`.

### Trader Tradovate OAuth

The server can act as Trader Desktop's Tradovate OAuth backend so the Tradovate client secret is never shipped in the desktop app. Trader starts the flow, opens the returned authorization URL in the user's browser, receives tokens only from this server, then connects directly to Tradovate with the returned access token.

Required server environment:

```dotenv
TRADOVATE_OAUTH_CLIENT_ID=replace-with-tradovate-client-id
TRADOVATE_OAUTH_CLIENT_SECRET=replace-with-tradovate-client-secret
TRADOVATE_OAUTH_REDIRECT_URI=https://licenses.example.com/api/trader/tradovate/oauth/callback
TRADOVATE_OAUTH_AUTHORIZE_URL=https://trader.tradovate.com/oauth
TRADOVATE_OAUTH_TOKEN_URL=https://live.tradovateapi.com/auth/oauthtoken
```

Optional:

```dotenv
TRADOVATE_OAUTH_SCOPES=
TRADOVATE_OAUTH_STATE_SECONDS=600
TRADOVATE_OAUTH_TOKEN_SECRET=replace-with-openssl-rand-base64-48
TRADOVATE_OAUTH_DEMO_AUTHORIZE_URL=
TRADOVATE_OAUTH_DEMO_TOKEN_URL=
TRADOVATE_LIVE_API_BASE_URL=https://live.tradovateapi.com/v1
TRADOVATE_DEMO_API_BASE_URL=https://demo.tradovateapi.com/v1
```

If `TRADOVATE_OAUTH_TOKEN_SECRET` is unset, token encryption derives from `AUTOEDGE_ADMIN_COOKIE_SECRET`. Use a dedicated random token secret in production.

`POST /api/trader/tradovate/oauth/start`

Request:

```json
{
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "email": "customer@example.com",
  "customer_id": "optional-internal-customer-id",
  "whop_user_id": "optional-whop-user-id",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0",
  "platform": "windows-x64",
  "channel": "stable",
  "environment": "live"
}
```

The server requires an active Trader license on the same device. It stores only hashed OAuth state/session handles, hashed license/device identity, and encrypted token material.

Response:

```json
{
  "status": "ok",
  "authorization_url": "https://trader.tradovate.com/oauth?response_type=code&client_id=...",
  "state": "opaque-one-time-state",
  "environment": "live",
  "expires_at": "2026-06-04T12:10:00Z"
}
```

`GET /api/trader/tradovate/oauth/callback`

Tradovate redirects the browser here with `code` and `state`. The server validates state, exchanges the code server-side, stores the encrypted Tradovate access token and any refresh token if Tradovate adds one, calls `/auth/me` for user metadata when possible, and returns a small browser success/failure page.

`POST /api/trader/tradovate/oauth/complete`

Request includes the original `state` plus the same license/device identity used at start. Response statuses are `pending`, `authorized`, `failed`, or `expired`. The `access_token` field is present only when authorized.

```json
{
  "status": "authorized",
  "access_token": "tradovate-access-token",
  "oauth_session_id": "opaque-refresh-session-handle",
  "user_id": "123456",
  "environment": "live",
  "api_base_url": "https://live.tradovateapi.com/v1",
  "expires_at": "2026-06-04T13:30:00Z"
}
```

`POST /api/trader/tradovate/oauth/refresh`

Request includes the `oauth_session_id` returned by `complete` plus the same license/device identity. The original OAuth `state` is intentionally short-lived and should not be treated as the durable refresh handle. Tradovate's official OAuth token response documents `access_token` and `expires_in`, not a refresh token. Their documented renewal path is `/auth/renewAccessToken`, which renews the current non-expired bearer token without creating a new session. This server endpoint uses the encrypted stored access token to call that renewal endpoint and returns the fresh access token to Trader. Trader Desktop may alternatively renew directly against Tradovate with its current access token; it does not need the client secret for renewal.

```json
{
  "oauth_session_id": "opaque-refresh-session-handle",
  "license_key": "AE-XXXX-XXXX-XXXX-XXXX-XXXX",
  "machine_fingerprint": "stable-client-machine-fingerprint",
  "app_version": "0.5.0"
}
```

Security behavior:

- `TRADOVATE_OAUTH_CLIENT_SECRET` never appears in any client response.
- Authorization codes, access tokens, refresh tokens, and client secrets are never written to audit logs.
- OAuth state expires by default after 10 minutes.
- `oauth_session_id` is returned only after authorization and is stored server-side as a hash plus encrypted copy.
- Completion and refresh are bound to the same active license/customer/device that started the flow.
- Stored tokens are encrypted and authenticated with a server-side secret.

Configure releases in `/admin/releases`. Artifact uploads are not handled by the web UI yet; copy package files under `AUTOEDGE_RELEASE_ARTIFACT_DIR` first, then register their relative path in the release form. If the file exists, the server calculates size and SHA-256 automatically.

Admin pages display and accept manual expiry times in US Eastern trading time (`ET`, America/New_York). The database and Trader API responses continue to store and return UTC timestamps with a `Z` suffix.

Trader Desktop release fields:

- Release type: `Trader Desktop`
- Product id: `trader-desktop`
- Channel: `stable`, `beta`, `canary`, or `internal`
- Platform: `macos-arm64` for current Apple Silicon macOS Trader builds; `windows-x64` remains supported for future Windows builds.
- Version and optional minimum supported version
- Published checkbox
- Audience mode: `all`, `allowlist`, `roles`, `percent`, or `disabled`
- Allowed customer ids, emails, or full license keys for allowlisted releases
- Required tags/roles such as `internal`, `tester`, `desktop_beta`, `duo_beta`, `duorc_beta`, or `early_access`
- Rollout percent from `0` to `100`, deterministic per customer/license and release
- Optional rollback reason
- Artifact path, optional download filename, optional size/SHA-256 override
- Optional signature and signature key id
- Release notes

Strategy package releases use release type `Strategy package`, choose the strategy in the licensed product field, and keep using feature ids such as `strategy.duo.runtime`.

Extension package releases use release type `Extension package`, choose the licensed extension product, and use the product slug as the package id. For Discord Notifier:

- Seed or create product: `Discord Notifier`, slug/package id `discord-notifier`, feature id `trader.notifications.discord`, Trader enabled, NT8 disabled.
- Copy one artifact per platform under `AUTOEDGE_RELEASE_ARTIFACT_DIR`, for example `extensions/discord-notifier/DiscordNotifier-1.0.0-macos-arm64.zip` and `extensions/discord-notifier/DiscordNotifier-1.0.0-windows-x64.zip`.
- Register two release rows in `/admin/releases`, both with release type `Extension package`, licensed product `Discord Notifier`, product/package id `discord-notifier`, and platform `macos-arm64` or `windows-x64`.
- Use the existing audience controls (`all`, `allowlist`, `roles/tags`, `percent`, or `disabled`) exactly as for strategy packages.

The database `scope` column is legacy app-vs-product-bound state. Product-bound packages, including `extension_package`, are stored with the existing product-bound scope while `release_type` is the authoritative package taxonomy exposed in manifests.

Customer tags are edited from the customer detail page under `Release targeting tags`. Tags are normalized to lowercase values and are included in license responses for diagnostic visibility.

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

Seed initial strategy and extension products:

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
TRADOVATE_OAUTH_CLIENT_ID=replace-with-tradovate-client-id
TRADOVATE_OAUTH_CLIENT_SECRET=replace-with-tradovate-client-secret
TRADOVATE_OAUTH_REDIRECT_URI=https://licenses.example.com/api/trader/tradovate/oauth/callback
TRADOVATE_OAUTH_AUTHORIZE_URL=https://trader.tradovate.com/oauth
TRADOVATE_OAUTH_TOKEN_URL=https://live.tradovateapi.com/auth/oauthtoken
TRADOVATE_OAUTH_TOKEN_SECRET=replace-with-openssl-rand-base64-48
TRADOVATE_LIVE_API_BASE_URL=https://live.tradovateapi.com/v1
TRADOVATE_DEMO_API_BASE_URL=https://demo.tradovateapi.com/v1
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
- NT8 endpoint: `https://solidparts.se/api/nt8/license/check`
- Public legal pages:
  - `https://solidparts.se/privacy`
  - `https://solidparts.se/terms`
- Trader release manifest: `https://solidparts.se/api/trader/releases/manifest`
- Trader release downloads: `https://solidparts.se/api/trader/releases/download/{token}`
- Trader Tradovate OAuth:
  - `POST https://solidparts.se/api/trader/tradovate/oauth/start`
  - `GET https://solidparts.se/api/trader/tradovate/oauth/callback`
  - `POST https://solidparts.se/api/trader/tradovate/oauth/complete`
  - `POST https://solidparts.se/api/trader/tradovate/oauth/refresh`
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
- `AUTOEDGE_TRADER_MAX_DEVICES` defaults to `1`. Blocked devices do not count. Devices are counted only after a successful active license check. Lowering a customer-specific limit is enforced on the next check for every existing device.
