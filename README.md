# AutoEdge Licensing Server

Secure licensing and entitlement service for AutoEdge TraderPro strategy access.

The server receives Whop AutoEdge entitlement updates, stores customer/product/subscription/device state, exposes a manual admin UI, and gives TraderPro clients a clear license decision without exposing Whop secrets to TraderPro.

## Features

- HTTPS-ready deployment behind Caddy or another reverse proxy.
- SQLite database with durable tables for customers, products/strategies/extensions, Whop packages, package grants, grant ledger, subscriptions, entitlements, devices, license checks, webhook events, admin users/sessions, and audit log.
- Whop server-to-server endpoint secured with Standard Webhooks HMAC headers or an explicit bearer token fallback.
- Admin web UI:
  - search customers
  - inspect Whop IDs, email, license key suffix, subscriptions, entitlements, devices, check-ins, and audit events
  - manually grant, revoke, suspend, or expire strategy access
  - set or replace expiry dates on manual strategy access
  - switch manual strategy access between dated expiry and Lifetime with no expiry
  - remove individual entitlement rows from a customer
  - block or unblock devices
  - enforce and override per-customer device limits
  - manage TraderPro strategy and extension products, including optional subscription URLs
  - map Whop plans/products to one or more licensed products with day grants
- TraderPro client endpoint:
  - activate/check by license key, email, customer id, or Whop user id
  - stores machine fingerprint hash and app version
  - returns licensed strategies, expiry, status, next check time, and grace period
- ES256 protection:
  - short-lived, customer/device/fingerprint-bound TraderPro license leases
  - offline-signed release envelopes verified during registration
  - independent license and release key families with explicit key IDs
  - transition controls for existing clients and unsigned historical releases
- No Whop API key or webhook secret is needed by TraderPro clients.

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

Products are internal licensed TraderPro capabilities, such as DUO, DUOrc, or optional TraderPro Desktop extensions. Whop Packages describe what Whop sells.

Configure each product's optional purchase/renewal link in `/admin/products`.
`subscription_url` accepts only absolute HTTPS URLs and can be cleared. The
server seeds DUO and DUOrc with
`https://whop.com/auto-edge/duo-nasdaq-futures-bot/`; all other product URLs
remain `null` until an administrator supplies a verified link.

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

Built-in seed products include the optional TraderPro Desktop extension:

- Display name: `Discord Notifier`
- Product slug/package id: `discord-notifier`
- Feature id: `trader.notifications.discord`
- Release type: `extension_package`

A customer must have an active grant for `trader.notifications.discord` to see or download Discord Notifier extension releases.

Built-in strategy products include MICH as a product/feature seed only:

- Display name: `MICH Runtime`
- Product slug/package id: `mich-runtime`
- Feature id: `strategy.mich.runtime`
- Release type: `strategy_package`
- Runtime entry assembly: `Trader.Strategies.Mich.dll`
- Initial runtime version: `0.1.0`
- Supported package platforms: `macos-arm64`, `windows-x64`, `linux-x64`

MICH is not generally released by the seed data. Register MICH release rows only after actual package artifacts are copied under `AUTOEDGE_RELEASE_ARTIFACT_DIR`.

The durable product catalog also seeds six TraderPro runtime packages:

| Product | Package/product slug | Feature id | Strategy id | Entry assembly | Initial technical version | Minimum TraderPro | Planned NT8 identity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| ORBO2 Runtime | `orbo-runtime` | `strategy.orbo.runtime` | `orbo` | `Trader.Strategies.Orbo.dll` | `0.1.0` | `0.1.182` | `2.0.2.1` |
| ORBO2ib Runtime | `orboib-runtime` | `strategy.orboib.runtime` | `orboib` | `Trader.Strategies.Orboib.dll` | `0.1.0` | `0.1.182` | `2.0.0.8` |
| ADAM Runtime | `adam-runtime` | `strategy.adam.runtime` | `adam` | `Trader.Strategies.Adam.dll` | `0.1.0` | `0.1.182` | `1.0.1.5` |
| EVE Runtime | `eve-runtime` | `strategy.eve.runtime` | `eve` | `Trader.Strategies.Eve.dll` | `0.1.0` | `0.1.182` | `1.0.2.6` |
| AURA Runtime | `aura-runtime` | `strategy.aura.runtime` | `aura` | `Trader.Strategies.Aura.dll` | `0.1.0` | `0.1.182` | `1.0.0.3` |
| EMAL Runtime | `emal-runtime` | `strategy.emal.runtime` | `emal` | `Trader.Strategies.Emal.dll` | `0.1.0` | `0.1.182` | `1.0.0.0` |

Each is a `strategy_package` for exact platforms `macos-arm64`,
`windows-x64`, and `linux-x64`. The migration and seed script create or
backfill product metadata only: they do not create release rows, artifacts,
Whop mappings, grants, or entitlements. Existing ORBO2 product rows are renamed
in place from `orbo2-runtime` / `strategy.orbo2.runtime` so their product id and
existing entitlement foreign keys are preserved.

When real TraderPro artifacts are ready, register product-bound, ES256-signed
release rows with the matching package slug, feature, technical version, and
platform. The planned NT8 identity is catalog metadata until an actual release
row is registered with `nt8_version` and `trader_revision`. A license can see
and request a download token only for releases whose product feature is active
in `licensed_strategies`.

These values mirror the Trader runtime package manifests: family-specific
display name, `Runtime` variant, internal Ed25519 package signature key
`main-2026-01`, entry assembly, strategy id, required feature, and minimum
TraderPro version `0.1.182`. Manifest `packages` catalog entries expose this
additive metadata even before a release exists for public products. Product
metadata may explicitly set `"catalog_visibility": "private"`; public is the
default when the setting is absent. A private product is omitted from all
customer manifest data unless the customer has an active entitlement and at
least one active, published release for the requested platform is visible after
channel, audience, allowlist/tag, and rollout checks. The catalog is
informational; it never grants access or creates a download.

Lifecycle handling:

- Trialing events set access through `trial_ends_at` when Whop provides it.
- Paid/valid/renewed events ensure access through the later of the event's period end and the configured package period. They never shorten later existing access. When Whop provides neither a period start nor end, configured days are applied once after current coverage as a compatibility fallback.
- Duplicate paid or renewal events for the same payment id or membership period are suppressed across event types by the grant ledger, so a payment and its matching membership update cannot add the same period twice.
- Package entitlements are tracked independently per membership, package, and licensed product. A standalone trial ending cannot expire the same product granted by an active bundle or another source.
- Normal expiration events do not revoke access or replace a later paid expiry. Future-dated access remains active until its stored expiry, and no-expiry Lifetime access remains Lifetime.
- `refund.created`, chargebacks, disputes, and `membership.went_invalid` are explicit revocation operations for the affected source. If no other source remains, the license response is `revoked`.
- Whop entitlement mutations use serialized SQLite write transactions so an older concurrent update cannot overwrite a later coverage date.
- Admin manual entitlement saves replace the selected row's status and expiry exactly, so an admin can shorten or extend a date and switch between dated access and Lifetime. Whop event processing remains monotonic and does not shorten existing Whop coverage.
- Expired, suspended, and revoked results are returned clearly to TraderPro so strategies can block access.

### TraderPro License Check

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
      "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
      "status": "active",
      "source": "whop",
      "expires_at": "2026-07-03T20:00:00Z"
    }
  ],
  "entitlement_states": [
    {
      "product_id": "product-id",
      "slug": "duo-runtime",
      "name": "DUO Runtime",
      "feature_id": "strategy.duo.runtime",
      "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
      "status": "active",
      "source": "whop",
      "expires_at": "2026-07-03T20:00:00Z",
      "changed_at": "2026-06-03T19:55:00Z"
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

TraderPro should allow strategy or extension access only when `status == "active"` and the required `feature_id` is present in `licensed_strategies`. The field name is legacy; it can contain any active TraderPro-enabled licensed product, including optional extensions such as `trader.notifications.discord`.

`entitlement_states` is additive display metadata for the current effective entitlement per product, including inactive `expired`, `revoked`, `suspended`, and audited `removed` states. TraderPro can use `expires_at` and `changed_at` to explain why an installed package no longer has access, but it must never grant access from this array; `licensed_strategies` and the signed TraderPro lease remain authoritative.

Manual Lifetime grants and other no-expiry entitlements are represented as `expires_at: null` on the affected `licensed_strategies` entries. The top-level `expires_at` is `null` only when all licensed strategies in the response have no expiry.

`device_limit_exceeded` means the customer already has the maximum number of active licensed, non-blocked machines. TraderPro must block strategy access and must not offer package downloads for that machine. If an admin lowers a customer limit below the current active device count, only the earliest active device(s) up to the new limit remain allowed; later devices are denied until the admin deauthorizes/resets devices or raises the limit. Admins can deauthorize a device, reset all devices for a customer, or set a customer-specific max device override in the customer detail page.

### NinjaTrader 8 License Check

`POST /api/nt8/license/check`

NT8 uses the same customers, Whop packages, manual grants, expiry dates, devices, device limits, and audit log as TraderPro Desktop. Products include explicit NT8 fields in the admin UI:

- `NT8 key`: the strategy key returned to NT8, for example `DUO` or `DUOrc`
- `TraderPro`: whether TraderPro Desktop should receive this product in license responses; the persisted field remains `trader_enabled`
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

### TraderPro Release Manifest

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

- `packages`: the active TraderPro product catalog and its current entitlement
  display state, including optional server-controlled `subscription_url`
  metadata. It is returned for active and blocking license decisions so Access
  & Updates can offer purchase or renewal links without granting access.
- `releases`: product-bound package releases only for features the customer is licensed and targeted to use.
- `app_update`: the TraderPro Desktop target release for the customer when it differs from `app_version`.

If `include_types` is omitted, both `strategy_package` and `trader_desktop` are included for backward compatibility. Future clients should request `extension_package` when they can install optional TraderPro extensions such as Discord Notifier.

Seeded strategy-package catalog entries add `required_features`,
`strategy_family`, `variant`, `strategy_id`, `entry_assembly`,
`initial_runtime_version`, `minimum_trader_version`, `supported_platforms`, and
the internal `package_signature` descriptor. These are package-template facts,
not evidence that an artifact or release row exists.

`installed_packages` is optional and lets the server compare each package against the version installed locally. If omitted, older clients still receive the same compatible release rows.

Release targeting is fully server-side. The client only sees releases it is
allowed to see. Admins can target releases by channel, customer id, email, full
license key, customer tags/roles, deterministic rollout percent, or disable the
release audience entirely. The customer tag `internal` is a global tester
designation: an actively licensed customer with that tag can see any
`channel=internal` release regardless of allowlist, roles, required-tag, or
percentage targeting. `audience_mode=disabled` remains invisible to everyone.

Platforms are exact selectors. The canonical values are `macos-arm64`,
`windows-x64`, and `linux-x64`; a Linux manifest selects only `linux-x64`
rows and never falls back to a macOS or Windows artifact.

Response:

```json
{
  "status": "active",
  "message": "Release manifest available.",
  "channel": "stable",
  "platform": "macos-arm64",
  "packages": [
    {
      "product_id": "product-id",
      "package_id": "duo-runtime",
      "display_name": "DUO",
      "product_name": "DUO",
      "feature_id": "strategy.duo.runtime",
      "release_type": "strategy_package",
      "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
      "license_status": "active",
      "license_source": "whop",
      "expires_at": "2026-07-03T20:00:00Z"
    }
  ],
  "releases": [
    {
      "id": "release-id",
      "release_id": "release-id",
      "scope": "strategy",
      "release_type": "strategy_package",
      "package_id": "duo-runtime",
      "display_name": "DUO",
      "product_name": "DUO",
      "strategy": "DUO",
      "product_id": "product-id",
      "feature_id": "strategy.duo.runtime",
      "required_features": ["strategy.duo.runtime"],
      "subscription_url": "https://whop.com/auto-edge/duo-nasdaq-futures-bot/",
      "version": "1.2.0",
      "nt8_version": "2.1.0.8",
      "trader_revision": 1,
      "installed_nt8_version": "2.1.0.7",
      "installed_trader_revision": 0,
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
    "display_name": "TraderPro Desktop",
    "product_name": "TraderPro Desktop",
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
      "path": "trader-desktop/TraderPro-Desktop-0.1.1-macos-arm64.zip",
      "filename": "TraderPro-Desktop-0.1.1-macos-arm64.zip",
      "size_bytes": 123456,
      "sha256": "hex-sha256",
      "signature": "optional-signature",
      "signature_key_id": "optional-key-id"
    },
    "release_notes": "TraderPro Desktop update",
    "rollback_reason": null
  },
  "license": {
    "status": "active"
  }
}
```

Extension package releases use the same `releases` array with `release_type: "extension_package"` and `scope: "extension"`. Discord Notifier release rows use `package_id: "discord-notifier"`, `display_name: "Discord Notifier"`, and `required_features: ["trader.notifications.discord"]`.

Strategy-package release objects also include nullable `nt8_version` and
`trader_revision` fields for the selected target release. When
`installed_packages` supplies that package's technical version, strategy-package
objects also include nullable `installed_nt8_version` and
`installed_trader_revision` fields resolved from the exact matching historical
release row. Unknown legacy versions and historical rows without a complete
identity pair return both installed fields as `null`. Requests without an
installed package version retain the previous response shape and omit the
installed identity fields. Desktop and extension releases omit all strategy
identity fields.

Existing releases keep their target identity fields `null`; no NT8 version is
inferred or backfilled. `nt8_version` must have exactly four numeric components
(multi-digit components are allowed), and `trader_revision` must be a
non-negative integer. Supply both values or leave both blank.

TraderPro should use the manifest only when `status == "active"`. Expired, revoked, suspended, blocked, device-limit-exceeded, or unknown customers receive an empty release list, `app_update: null`, and the same blocking license status.

`packages[].subscription_url` is nullable. A `null` value means no verified
purchase link is configured and clients should omit the subscribe/renew action.
`packages[].license_status` is display metadata only. Neither the package
catalog nor its subscription URL grants access; `licensed_strategies`, the
signed TraderPro lease, release selection, download-token checks, and resolved
download authorization remain authoritative.

`action` is one of:

- `update`: target version is newer than the installed/current version.
- `rollback`: target version is lower and the server has explicitly directed rollback by marking the release required or setting a rollback reason.
- `current`: target version equals the installed/current version.

Rollback is server-directed. TraderPro Desktop and strategies must not infer that a newer local version is valid if the server returns a lower `target_version` with `action: "rollback"`.

### TraderPro Release Download

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

The server checks the license, device limit, platform, and release targeting again before issuing a short-lived download token. Product-bound package downloads, including `strategy_package` and `extension_package`, are allowed only when the license includes the required product feature. TraderPro Desktop downloads are allowed for active licenses only when the customer is targeted for that app release. A customer cannot download a release merely by knowing its `release_id`.

Response:

```json
{
  "status": "ok",
  "download_url": "https://licenses.example.com/api/trader/releases/download/token-value",
  "expires_at": "2026-06-04T12:00:00Z"
}
```

`GET /api/trader/releases/download/{token}` streams the artifact. Tokens are stored as hashes, expire quickly, and each download attempt is recorded in `release_downloads`.

### TraderPro Tradovate OAuth

The server can act as TraderPro Desktop's Tradovate OAuth backend so the Tradovate client secret is never shipped in the desktop app. TraderPro starts the flow, opens the returned authorization URL in the user's browser, receives tokens only from this server, then connects directly to Tradovate with the returned access token.

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

The server requires an active TraderPro license on the same device. It stores only hashed OAuth state/session handles, hashed license/device identity, and encrypted token material.

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

Request includes the `oauth_session_id` returned by `complete` plus the same license/device identity. The original OAuth `state` is intentionally short-lived and should not be treated as the durable refresh handle. Tradovate's official OAuth token response documents `access_token` and `expires_in`, not a refresh token. Their documented renewal path is `/auth/renewAccessToken`, which renews the current non-expired bearer token without creating a new session. This server endpoint uses the encrypted stored access token to call that renewal endpoint and returns the fresh access token to TraderPro. TraderPro Desktop may alternatively renew directly against Tradovate with its current access token; it does not need the client secret for renewal.

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

Admin pages display and accept manual expiry times in US Eastern trading time (`ET`, America/New_York). The database and TraderPro API responses continue to store and return UTC timestamps with a `Z` suffix.

TraderPro Desktop release fields:

- Release type label: `TraderPro Desktop`; persisted release type: `trader_desktop`
- Product id: `trader-desktop`
- Channel: `stable`, `beta`, `canary`, or `internal`
- Platform: `macos-arm64` for Apple Silicon macOS builds, `windows-x64` for Windows builds, or `linux-x64` for Linux x64 builds.
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

New first-install presentation names are:

- Installed macOS app bundle: `TraderPro.app`
- macOS disk image: `TraderPro-Desktop-<version>-macos-arm64.dmg`
- macOS ZIP: `TraderPro-Desktop-<version>-macos-arm64.zip`
- Windows installer: `TraderPro-Desktop-<version>-windows-x64-Setup.exe`
- Windows portable ZIP: `TraderPro-Desktop-<version>-windows-x64.zip`
- Linux x64 artifact: `TraderPro-Desktop-<version>-linux-x64.<format>` using the actual format produced by the client release workflow.

Store these artifacts under the existing `trader-desktop` artifact directory. Desktop releases are identified by `release_type = trader_desktop`, `scope = app`, and `product_key = trader-desktop`, not by a filename prefix. Previously registered `Trader-Desktop-*`, `Trader-Setup-*`, or other historical filenames and their tokenized download URLs remain valid; do not rename files or rewrite historical release rows. New desktop releases with no explicit notes use `TraderPro Desktop update`.

Strategy package releases use release type `Strategy package`, choose the strategy in the licensed product field, and keep using feature ids such as `strategy.duo.runtime`.

Strategy release identity and ordering are maintained separately:

- A new NT8 release changes `nt8_version` and normally resets
  `trader_revision` to `0`.
- A TraderPro-only strategy release keeps the same `nt8_version` and increments
  `trader_revision`.
- The existing technical `version` remains independently monotonic. Continue
  using it for update ordering, installed/current/target comparisons, artifact
  matching, rollback, and release uniqueness; do not replace it with the
  customer-facing NT8/TraderPro identity.

Register a separate row and real artifact for every published platform:
`macos-arm64`, `windows-x64`, and/or `linux-x64`. Platform rows may carry the
same `nt8_version` and `trader_revision` values. Never copy another platform's
row or register a placeholder artifact; manifests and download tokens match the
requested platform exactly.

For MICH, use seeded product `MICH Runtime` with product/package id `mich-runtime`, release type `strategy_package`, version `0.1.0`, and feature id `strategy.mich.runtime`. Copy one real artifact per published platform under `AUTOEDGE_RELEASE_ARTIFACT_DIR`, then register a separate `Strategy package` release with the matching `macos-arm64`, `windows-x64`, or `linux-x64` platform. Do not register placeholder releases without artifacts, and do not add MICH parity claims while May 3, 2026 through June 16, 2026 parity is pending.

ORBO2, ORBO2ib, ADAM, EVE, AURA, and EMAL follow the same artifact-first workflow
using the seeded catalog values above. Their initial technical version is
`0.1.0` and their catalog minimum TraderPro version is `0.1.182`. New or
published release registrations inherit that minimum when omitted and reject a
lower value. Use the listed planned NT8 identity only when the corresponding
real signed artifact is ready, paired with an explicit non-negative TraderPro
revision. Do not create placeholder releases or reuse an artifact from another
platform.

The current Trader thin wrappers call the shared `release-mich-package.sh`,
whose fallback minimum is `0.1.0`; the wrappers do not override it. Until that
Trader-side default is changed, each real release invocation must explicitly
pass `--min-trader-version 0.1.182`. Remaining release-time inputs are the real
platform artifact, confirmed technical version, confirmed NT8 identity and
Trader revision, channel/audience/rollout, release notes, and the offline ES256
release-envelope signature.

EMAL is seeded without a release, artifact, entitlement, Whop package, package
grant, subscription URL, or commercial mapping. Its first real release must use
the client wrapper `scripts/release-emal-package.sh` once per platform with
`--min-trader-version 0.1.182`, `--nt8-version 1.0.0.0`, and
`--trader-revision 0`. Start with `--channel internal --audience-mode allowlist`
and at least one explicit `--allowed-customer-ids`, `--allowed-emails`, or
`--allowed-license-keys` value. An entitled customer tagged `internal` also
qualifies for every internal-channel release without being copied into each
release allowlist. A customer without that global tag must still match the
release's explicit allowlist or required tags. A disabled release is invisible
to everyone, including internal-tagged customers. Download-token issuance
rechecks the same entitlement and audience rules. The EMAL product metadata
enforces this initial policy server-side: only `internal` or `canary` channels
and only `allowlist` or `disabled` audience modes are accepted.

Extension package releases use release type `Extension package`, choose the licensed extension product, and use the product slug as the package id. For Discord Notifier:

- Seed or create product: `Discord Notifier`, slug/package id `discord-notifier`, feature id `trader.notifications.discord`, TraderPro enabled, NT8 disabled.
- Copy one real artifact per published platform under `AUTOEDGE_RELEASE_ARTIFACT_DIR`, for example `extensions/discord-notifier/DiscordNotifier-1.0.0-linux-x64.zip` for Linux.
- Register one release row per artifact in `/admin/releases`, each with release type `Extension package`, licensed product `Discord Notifier`, product/package id `discord-notifier`, and the exact matching platform (`macos-arm64`, `windows-x64`, or `linux-x64`).
- Use the existing audience controls (`all`, `allowlist`, `roles/tags`, `percent`, or `disabled`) exactly as for strategy packages.

The database `scope` column is legacy app-vs-product-bound state. Product-bound packages, including `extension_package`, are stored with the existing product-bound scope while `release_type` is the authoritative package taxonomy exposed in manifests.

Customer tags are edited from the customer detail page under `Release targeting tags`. Tags are normalized to lowercase values and are included in license responses for diagnostic visibility.

## ES256 TraderPro Protection

Active TraderPro license responses now include the additive
`license_lease` object when the server's online ES256 key is configured.
Blocking responses and unsigned local-transition configurations return
`license_lease: null`. Release manifests expose the same signed lease under
`license.license_lease`. Existing response fields and the NT8 HMAC lease are
unchanged.

Release `artifact.signature` values can contain compact ES256 release envelopes.
Every supplied signature is verified during release registration, including
when signature enforcement is disabled. Existing unsigned rows remain readable
and downloadable when inactive. Production has completed the server-side
transition and runs with `AUTOEDGE_REQUIRE_RELEASE_SIGNATURES=true`; unsigned
historical rows remain stored but are inactive and unpublished.

The exact compact-token bytes, 64-byte `R || S` signature representation,
license and release JSON contracts, key provisioning and rotation, client
pinning, disaster recovery, revocation, signing commands, and audit procedure
are documented in [docs/es256-protection.md](docs/es256-protection.md).

## Local Development

```bash
cd /Users/andreas.geidnert/Dev/autoedge-licensing-server
cp .env.example .env
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
mkdir -p data/artifacts
AUTOEDGE_ADMIN_COOKIE_SECRET="$(openssl rand -base64 48)" \
AUTOEDGE_WHOP_BEARER_TOKEN="local-test-token" \
AUTOEDGE_COOKIE_SECURE=false \
AUTOEDGE_SKIP_RUNTIME_VALIDATION=1 \
.venv/bin/python -m autoedge_licensing.app
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
.venv/bin/python -m unittest discover -s tests
```

## Debian Deployment

Assumptions:

- Debian host with Python 3.11+.
- DNS for the chosen HTTPS host points to the server.
- nginx or Caddy terminates HTTPS and proxies to the local Python service.

Install packages:

```bash
sudo apt update
sudo apt install -y python3 python3-venv git nginx certbot python3-certbot-nginx
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

Create the service virtual environment and install the pinned runtime set:

```bash
sudo python3 -m venv /opt/autoedge-licensing/.venv
sudo /opt/autoedge-licensing/.venv/bin/python -m pip install \
  -r /opt/autoedge-licensing/requirements.txt
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
AUTOEDGE_TRADER_LICENSE_SIGNING_PRIVATE_KEY_PATH=/etc/autoedge-licensing/keys/license-2026-01-private.pem
AUTOEDGE_TRADER_LICENSE_SIGNING_KEY_ID=license-2026-01
AUTOEDGE_TRADER_LICENSE_VERIFICATION_KEYS='{"license-2026-01":"/etc/autoedge-licensing/keys/license-2026-01-public.pem"}'
AUTOEDGE_TRADER_LICENSE_ISSUER=solidparts.se
AUTOEDGE_TRADER_LICENSE_AUDIENCE=traderpro
AUTOEDGE_RELEASE_VERIFICATION_KEYS='{"release-2026-01":"/etc/autoedge-licensing/release-public/release-2026-01.pem"}'
AUTOEDGE_REQUIRE_RELEASE_SIGNATURES=true
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

Provision the online license-signing key outside the repository. The release
private key must never be generated or stored on this server:

```bash
sudo install -d -o root -g autoedge -m 0750 /etc/autoedge-licensing/keys
sudo install -o root -g autoedge -m 0640 license-2026-01-private.pem \
  /etc/autoedge-licensing/keys/license-2026-01-private.pem
sudo install -o root -g autoedge -m 0644 license-2026-01-public.pem \
  /etc/autoedge-licensing/keys/license-2026-01-public.pem
```

Provision only the offline release-signing public key on the server. The
matching private key remains on the protected release/build machine:

```bash
sudo install -d -o root -g root -m 0755 /etc/autoedge-licensing/release-public
sudo install -o root -g root -m 0644 release-2026-01.pem \
  /etc/autoedge-licensing/release-public/release-2026-01.pem
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
- TraderPro endpoint: `https://solidparts.se/api/trader/license/check`
- NT8 endpoint: `https://solidparts.se/api/nt8/license/check`
- Public legal pages:
  - `https://solidparts.se/privacy`
  - `https://solidparts.se/terms`
- TraderPro release manifest: `https://solidparts.se/api/trader/releases/manifest`
- TraderPro release downloads: `https://solidparts.se/api/trader/releases/download/{token}`
- TraderPro Tradovate OAuth:
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
- Release verification key: `release-2026-01` at
  `/etc/autoedge-licensing/release-public/release-2026-01.pem`; production
  requires signed published releases

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
