# AutoEdge Licensing Server Codex Memory

Last refreshed: 2026-07-10

## Repository Shape

- `autoedge_licensing/app.py` is the stdlib WSGI entrypoint, router, admin HTML,
  JSON response layer, release download streaming, CSRF/session cookie handling,
  in-memory per-IP rate limiter, and redacting WSGI access-log handler.
- `autoedge_licensing/service.py` owns business logic: customers, products, Whop
  packages, entitlements, device limits, release manifests, download tokens,
  NT8 checks, audit logging, and Whop event processing.
- `autoedge_licensing/db.py` applies ordered SQL migrations from `migrations/`
  and opens SQLite connections with foreign keys and WAL enabled.
- `autoedge_licensing/config.py` reads env vars and validates required runtime
  secrets.
- `autoedge_licensing/security.py` contains hashing, signing, password hashing,
  cookie parsing, bearer-token auth, and Standard Webhooks verification.
- `scripts/create_admin.py` creates an admin user after applying migrations.
- `scripts/seed_products.py` seeds default strategy products
  DUO, DUOrc, ORBO2, ORBOib, ADAM, EVE, MICH, and HUGO, plus the TraderPro
  Desktop extension product Discord Notifier.
- `deploy/` contains nginx and Caddy reverse-proxy examples.
- `systemd/autoedge-licensing.service` runs the app with `/etc/autoedge-licensing.env`
  and writes only to `/var/lib/autoedge-licensing`.
- `tests/` uses `unittest` and temp SQLite DBs; there is no pytest requirement.

There was no existing `AGENTS.md` or `docs/` tree before this memory refresh.

## Current Git State At Refresh

- Branch: `main`
- Tracking state: `main...origin/main [ahead 8]`
- Worktree before documentation edits: clean
- Recent commits included work around customer entitlement counts, effective
  entitlements display, Whop activation/cancel-at-period-end handling, reduced
  device limit enforcement, and nginx forwarding for NT8.

Do not reset, rebase, or discard these local commits unless the user explicitly
asks.

## Runtime And Local Workflow

The app is designed to run without external Python runtime dependencies.
`pyproject.toml` declares Python `>=3.11` and an empty dependency list.

Local start, following `README.md`:

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

Common commands:

```bash
AUTOEDGE_DATABASE_PATH=data/autoedge.db python3 scripts/create_admin.py admin
AUTOEDGE_DATABASE_PATH=data/autoedge.db python3 scripts/seed_products.py
python3 -m unittest discover -s tests
```

## Environment And Secrets

Key environment variables:

- `AUTOEDGE_DATABASE_PATH`, default `data/autoedge.db`
- `AUTOEDGE_BIND_HOST`, default `127.0.0.1`
- `AUTOEDGE_BIND_PORT`, default `8788`
- `AUTOEDGE_PUBLIC_BASE_URL`
- `AUTOEDGE_ADMIN_COOKIE_SECRET`, required at runtime and at least 32 chars
- `WHOP_WEBHOOK_SECRET`, preferred production webhook secret
- `AUTOEDGE_WHOP_BEARER_TOKEN`, fallback for local or non-Whop server testing
- `AUTOEDGE_LICENSE_LEASE_SECRET`, optional NT8 lease secret; defaults to admin
  cookie secret and must also be at least 32 chars
- `AUTOEDGE_TRADER_MAX_DEVICES`, default `1`
- `AUTOEDGE_RELEASE_ARTIFACT_DIR`, default `data/artifacts`
- `TRADOVATE_OAUTH_CLIENT_ID`, `TRADOVATE_OAUTH_CLIENT_SECRET`, and
  `TRADOVATE_OAUTH_REDIRECT_URI`, required together to enable Tradovate OAuth
- `TRADOVATE_OAUTH_AUTHORIZE_URL`, default `https://trader.tradovate.com/oauth`
- `TRADOVATE_OAUTH_TOKEN_URL`, default
  `https://live.tradovateapi.com/auth/oauthtoken`
- `TRADOVATE_OAUTH_TOKEN_SECRET`, optional dedicated encryption secret for
  stored Tradovate tokens; defaults to `AUTOEDGE_ADMIN_COOKIE_SECRET`
- `TRADOVATE_OAUTH_SCOPES`, optional; official Tradovate OAuth examples do not
  require a scope parameter
- `TRADOVATE_OAUTH_STATE_SECONDS`, default `600`
- `TRADOVATE_OAUTH_DEMO_AUTHORIZE_URL`,
  `TRADOVATE_OAUTH_DEMO_TOKEN_URL`, `TRADOVATE_LIVE_API_BASE_URL`, and
  `TRADOVATE_DEMO_API_BASE_URL` for live/demo URL overrides

Production should use `WHOP_WEBHOOK_SECRET`. Treat bearer-token auth as a local
testing fallback, not the production default.

## Public And Admin Endpoints

Implemented routes in `AutoEdgeApp.route`:

- `GET /healthz`
- `GET /privacy`
- `GET /terms`
- `POST /api/whop/entitlements`
- `POST /api/trader/license/check`
- `POST /api/trader/license/activate`
- `POST /api/nt8/license/check`
- `POST /api/trader/releases/manifest`
- `POST /api/trader/releases/download-token`
- `GET /api/trader/releases/download/{token}`
- `POST /api/trader/tradovate/oauth/start`
- `GET /api/trader/tradovate/oauth/callback`
- `POST /api/trader/tradovate/oauth/complete`
- `POST /api/trader/tradovate/oauth/refresh`
- `/admin/login`, `/admin/logout`, `/admin/password`
- `/admin/customers`, `/admin/customers/{id}/...`
- `/admin/products`
- `/admin/packages`
- `/admin/releases`
- `/admin/devices/{id}/...`

Admin pages are plain server-rendered HTML. They use signed cookies,
CSRF tokens derived from the session token plus admin cookie secret, and display
admin timestamps in US Eastern time.

## Licensing Contracts

TraderPro Desktop license checks:

- Accept license key, email, customer id, or Whop user id; require
  `machine_fingerprint`.
- Return `licensed_strategies` with internal product id, slug, name,
  `feature_id`, status, source, and expiry.
- Manual Lifetime grants and other no-expiry entitlements are stored as
  `expires_at = NULL`; affected strategy entries return `expires_at: null`, and
  the top-level expiry is `null` only when every licensed strategy has no
  expiry.
- Strategy access should be allowed only when `status == "active"` and the
  required `feature_id` is present.

NT8 license checks:

- Use the same customers, entitlements, devices, device limits, and audit log as
  TraderPro Desktop.
- Products have `nt8_strategy_key`, `trader_enabled`, and `nt8_enabled`.
- Return `licensed: true`, `strategy_keys`, and an HMAC-signed opaque lease when
  active.
- Manual Lifetime grants and other no-expiry entitlements also return
  `expires_at: null` on affected NT8 strategy entries, with a `null` top-level
  expiry only when every licensed strategy has no expiry.
- If a requested strategy is not licensed, return `unlicensed_strategy` and no
  lease.
- NT8 leases are not public-key offline-verifiable. Do not embed server secrets
  in NT8; if true offline verification is required, add asymmetric signing and
  ship only the public key.

Keep blocking states explicit for clients. Important statuses include
`unknown_customer`, `unlicensed`, `unlicensed_strategy`, `expired`, `revoked`,
`suspended`, `device_blocked`, `device_limit_exceeded`, `invalid_request`, and
`rate_limited`.

## Tradovate OAuth

TraderPro Desktop uses this licensing server as the Tradovate OAuth backend so the
Tradovate client secret never ships in the desktop app.

Flow:

- `POST /api/trader/tradovate/oauth/start` validates the current TraderPro license
  and device with the same device-limit logic as license checks, creates a
  random one-time state, stores only `sha256(state)`, and returns a Tradovate
  authorization URL plus the raw state for the desktop to poll with.
- `GET /api/trader/tradovate/oauth/callback` validates state and expiry, then
  exchanges `code` server-side at the configured Tradovate `/auth/oAuthToken`
  URL using `TRADOVATE_OAUTH_CLIENT_SECRET`. It returns only small HTML
  success/failure pages to the browser.
- `POST /api/trader/tradovate/oauth/complete` accepts the original state and
  the same license/device identity. It returns `pending`, `authorized`,
  `failed`, or `expired`; `access_token` and `oauth_session_id` are present only
  when authorized.
- `POST /api/trader/tradovate/oauth/refresh` accepts the `oauth_session_id`
  returned by `complete` and the same license/device identity, decrypts the
  stored access token, calls Tradovate `/auth/renewAccessToken`, stores the
  renewed token, and returns the new access token. The original OAuth `state` is
  a short-lived correlation value, not the durable refresh handle.

Tradovate's official OAuth token response documents `access_token` and
`expires_in`, not a refresh token. If Tradovate adds `refresh_token`, the schema
has a nullable encrypted column for it, but current refresh behavior is based on
renewing the existing non-expired bearer token. TraderPro Desktop can also renew
directly with Tradovate using its current access token; that does not require
the client secret.

Security:

- Never log or persist OAuth codes, access tokens, refresh tokens, or client
  secrets in plaintext.
- The stdlib WSGI request handler must keep redacting sensitive query params
  such as `code`, `state`, tokens, and `client_secret`; OAuth callbacks include
  authorization codes in the URL query string.
- Stored token material uses stdlib authenticated encryption helpers derived
  from `TRADOVATE_OAUTH_TOKEN_SECRET` or the admin cookie secret fallback.
- Completion and refresh must stay bound to the same active customer/device that
  started OAuth.
- Pending OAuth states expire after `TRADOVATE_OAUTH_STATE_SECONDS`; old
  pending/failed/expired rows are cleaned on new starts.

## Whop Entitlements And Package Mapping

Whop events enter through `POST /api/whop/entitlements`.

Security:

- Prefer Standard Webhooks headers: `webhook-id`, `webhook-timestamp`, and
  `webhook-signature`.
- Verification must use the exact raw request body.
- The endpoint is idempotent by `webhook-id`.

Mapping model:

- Internal `products` are licensed TraderPro capabilities. Most are TraderPro/NT8
  strategies, but the table also holds optional TraderPro Desktop extensions.
- Discord Notifier is the first optional extension product: display name
  `Discord Notifier`, product slug/package id `discord-notifier`, feature id
  `trader.notifications.discord`, TraderPro enabled, NT8 disabled; the persisted
  enablement field remains `trader_enabled`.
- `whop_packages` represent what Whop sells.
- A package can grant one or more internal products through
  `whop_package_grants`.
- `plan_id` takes precedence over `product_id` when resolving a package.
- `is_ignored` means a known Whop access pass is intentionally non-licensing.
- Old Vercel-style mappings such as
  `plan_x=204,30:337,30:1175,30` should remain represented as one package with
  multiple grant rows, not as direct one-product assumptions.

Grant behavior:

- Trial events use `trial_ends_at` when Whop provides it.
- Paid, valid, and renewed events are monotonic ensure-through updates. The
  target is the later of the explicit Whop period end and the configured
  package period; only the compatibility case with no period start or end adds
  configured days once after current coverage.
- Duplicate paid and renewal events for the same payment or membership period
  are suppressed across event types by `license_grant_ledger`. Trial updates
  with a genuinely later `trial_ends_at` may extend coverage, while delivery of
  the same trial date remains idempotent.
- Whop package entitlements are separate sources per membership, package, and
  licensed product. Effective access uses the active source with Lifetime or
  the latest expiry, so one source ending cannot mask another active source.
- Normal expiration is not revocation: it cannot shorten later access, block a
  future paid expiry, or convert no-expiry Lifetime access into dated access.
  Refunds, chargebacks, disputes, and invalid membership events remain explicit
  source revocations.
- Whop and manual entitlement mutations use `BEGIN IMMEDIATE` transactions to
  serialize concurrent SQLite writers. Coverage dates and subscription period
  dates are updated monotonically.

## Releases And Downloads

The desktop product presentation name is `TraderPro Desktop` (`TraderPro` in
short labels). This is presentation-only. Keep `/api/trader/*`, release type
`trader_desktop`, product key/id `trader-desktop`, client type
`trader_desktop`, the `trader-desktop` artifact directory, `trader_enabled`,
`AUTOEDGE_TRADER_*`, package/feature ids, and all existing customer, device,
license, and release data unchanged.

New first-install presentation filenames use `TraderPro.app` and
`TraderPro-Desktop-<version>-<platform>` artifact names documented in
`README.md`. Artifact classification is metadata-driven, never filename-prefix
driven. Existing `Trader-Desktop-*`, `Trader-Setup-*`, and arbitrary historical
artifact names and URLs remain downloadable from their existing release rows.
Do not rename stored files, rewrite old release notes, or duplicate historical
release rows for the rebrand. New desktop releases without explicit notes use
`TraderPro Desktop update`. Manifest and download-token release objects expose
optional `display_name`/`product_name` values of `TraderPro Desktop` while all
compatibility identifiers remain unchanged.

Release types:

- `strategy_package`
- `extension_package`
- `trader_desktop`

`extension_package` is the generic release type for optional TraderPro Desktop
extensions. Discord Notifier uses this type. The persisted
`trader_releases.scope` column is legacy app-vs-product-bound state; product
bound packages such as `strategy_package` and `extension_package` still use the
existing product-bound scope internally, while `release_type` is authoritative
in manifests.

Supported platforms:

- `macos-arm64`
- `windows-x64`

Channels, in increasing exposure:

- `stable`
- `beta`
- `canary`
- `internal`

Release targeting is server-side. The client only sees releases it is allowed to
see. Audience modes are `all`, `allowlist`, `roles`, `percent`, and `disabled`.
Targeting can use customer ids, emails, full license keys, customer tags/roles,
or deterministic rollout percent.

Download flow:

- Manifest returns visible releases and app updates only for active licenses.
- If `include_types` is omitted, manifests intentionally keep the old default:
  `strategy_package` and `trader_desktop`. Clients that support optional
  extensions must request `extension_package`.
- Product-bound release manifest rows now include `package_id`, `display_name`,
  `required_features`, `release_id`, artifact `path`/`filename`,
  `license_status`, and product grant `expires_at` in addition to the existing
  strategy-package fields.
- `/api/trader/releases/download-token` rechecks license, device limit, platform,
  and targeting before issuing a short-lived token. Product-bound packages,
  including `extension_package`, require an active grant for the release product.
- `GET /api/trader/releases/download/{token}` streams the artifact and records
  attempts in `release_downloads`.
- Artifact uploads are not in the admin UI. Copy files under
  `AUTOEDGE_RELEASE_ARTIFACT_DIR`, then register relative paths in
  `/admin/releases`.
- To publish Discord Notifier, seed/create the product, copy one artifact for
  `macos-arm64` and one for `windows-x64`, and register two `Extension package`
  releases with product/package id `discord-notifier`.
- MICH is seeded as a strategy product only: slug/package id `mich-runtime`,
  display name `MICH Runtime`, feature id `strategy.mich.runtime`, runtime
  entry assembly `Trader.Strategies.Mich.dll`, initial runtime version `0.1.0`,
  and supported package platforms `macos-arm64` and `windows-x64`. There are no
  seeded MICH release rows. Publish MICH only after copying actual platform
  artifacts under `AUTOEDGE_RELEASE_ARTIFACT_DIR`, then register
  `Strategy package` releases with product/package id `mich-runtime`,
  release type `strategy_package`, version `0.1.0`, and the matching platform.
  MICH parity remains pending; do not add parity claims.

Rollback behavior is server-directed. Clients must not assume that a newer local
version is valid when the server returns a lower `target_version` with
`action: "rollback"`.

## Schema And Migration Notes

Migrations are applied lexicographically from `migrations/*.sql` and recorded in
`schema_migrations`.

Current migration sequence:

- `001_init.sql`: customers, products, subscriptions, entitlements, devices,
  license checks, audit log, webhook events, admin users, and sessions.
- `002_whop_packages.sql`: package mapping tables and grant ledger.
- `003_remove_legacy_nt_package_grants.sql`: rebuilds package grants without
  legacy NT package columns.
- `004_trader_releases.sql`: release records, download tokens, and downloads.
- `005_device_limits.sql`: customer max-device override and device licensed
  timestamps.
- `006_release_types.sql`: release type, product key, publishing fields, and
  signature key id.
- `007_release_targeting.sql`: customer tags, release audiences, rollout
  percent, and rollback reason.
- `008_nt8_licensing.sql`: NT8 strategy key/product enablement and per-client
  device/check columns.
- `009_blank_customer_whop_ids.sql`: cleans legacy blank customer Whop user and
  member ids to `NULL`.
- `010_tradovate_oauth.sql`: Tradovate OAuth state rows with hashed
  state, license/device binding, encrypted token columns, expiry/failure
  metadata, and lookup indexes.
- `011_tradovate_oauth_sessions.sql`: adds separate hashed/encrypted
  `oauth_session_id` storage so Desktop refresh uses a session handle instead
  of the short-lived OAuth `state`.
- `012_seed_mich_strategy_product.sql`: idempotently seeds/backfills the MICH
  strategy product metadata without creating release rows.
- `013_entitlement_sources.sql`: adds the internal package source key to
  entitlements, changes external-id uniqueness to include that source, and
  splits legacy multi-package entitlement rows from grant-ledger history.

Customer Whop user/member identifiers are optional. Service writes should strip
them and treat blank strings as absent so manual admin-created customers do not
store empty strings in unique columns.

For schema changes, add a new numbered SQL migration. Avoid modifying already
applied migrations unless the user explicitly asks for a history rewrite.

## Device Limits

Default max devices is `AUTOEDGE_TRADER_MAX_DEVICES`, currently defaulting to
`1`. Customers can have an admin override.

Important behavior:

- Blocked devices do not count.
- Devices are counted only after a successful active license check.
- If an admin lowers the max below current active devices, earliest active
  devices remain allowed and later devices are denied on their next check.
- Admin can block/unblock individual devices, reset all customer devices, or set
  a customer-specific device limit.

## Admin UI Gotchas

- Admin expiry inputs and display are ET (`America/New_York`), but database and
  API timestamps are UTC with `Z`.
- Manual strategy access can be set to `Date/time` or `Lifetime`; `Lifetime`
  uses the existing nullable `entitlements.expires_at` storage and should render
  as Lifetime for active/trialing no-expiry rows.
- Manual `active`/`trialing` saves are monotonic ensure-through operations. They
  do not shorten an existing later expiry, and a Lifetime source cannot be
  changed back to dated access. Explicit expired/revoked/suspended statuses
  remain available for deliberate blocking actions.
- Customer entitlement rows have a per-row Remove action in the visible
  Entitlements table. It deletes the selected `entitlements` row and writes an
  `entitlement.removed` audit event; Whop grant ledger rows keep their nullable
  entitlement reference.
- Product/admin pages intentionally hide internal slugs and feature ids in user
  facing tables where tests assert that behavior.
- Customer tags are normalized to lowercase release-targeting tags.
- Admin password changes revoke active sessions by forcing a sign-in cycle.

## Deployment Memory

Current deployment documented in `README.md`:

- Host: `solidparts.se`
- Admin UI: `https://solidparts.se/admin/login`
- TraderPro endpoint: `https://solidparts.se/api/trader/license/check`
- NT8 endpoint: `https://solidparts.se/api/nt8/license/check`
- TraderPro manifest: `https://solidparts.se/api/trader/releases/manifest`
- Public legal pages: `https://solidparts.se/privacy` and
  `https://solidparts.se/terms`
- TraderPro Tradovate OAuth: `https://solidparts.se/api/trader/tradovate/oauth/start`,
  `/callback`, `/complete`, and `/refresh`
- Whop endpoint: `https://solidparts.se/api/whop/entitlements`
- Service unit: `autoedge-licensing.service`
- App directory: `/opt/autoedge-licensing`
- Database: `/var/lib/autoedge-licensing/autoedge.db`
- Artifacts: `/var/lib/autoedge-licensing/artifacts`
- Environment file: `/etc/autoedge-licensing.env`

Operational SSH notes:

- Use `root@192.168.50.141` for release/deployment server SSH.
- Prefer plain interactive-style commands, for example
  `ssh root@192.168.50.141` and `scp <file> root@192.168.50.141:/tmp/<file>`.
- Do not rely on `ssh -o BatchMode=yes` or BatchMode `scp`; BatchMode can fail
  even when normal SSH works from Codex.
- The current `/opt/autoedge-licensing` production directory is a deployed file
  tree, not a Git working tree. Do not plan on running `git pull` there.
- For a production release, create an exact `git archive` of the committed
  revision locally, verify its SHA-256 before and after upload, extract it to a
  temporary server directory, and run `python3 -m unittest discover -s tests`
  from staging. Before copying it over `/opt/autoedge-licensing`, create a code
  archive and an online SQLite `.backup` under `/var/backups`; verify the backup
  with `PRAGMA quick_check`. Restart `autoedge-licensing`, confirm the new
  migration in `schema_migrations`, run `PRAGMA quick_check` on the live DB,
  and check both local app health and publicly proxied routes.
- nginx does not currently expose `/healthz` on `solidparts.se`; the local
  `http://127.0.0.1:8788/healthz` endpoint is authoritative for service health.
  Use public routes such as `/privacy` and `/admin/login` to verify external
  proxy reachability.
- For release registration, SSH to the server, `cd /opt/autoedge-licensing`,
  source `/etc/autoedge-licensing.env`, then use the existing
  `autoedge_licensing` service code and `LicensingService.upsert_release`,
  matching the fields used by the TraderPro release scripts.

nginx must proxy root-relative `/privacy`, `/terms`, `/admin`, `/api/trader/`,
`/api/nt8/`, and exact `/api/whop/entitlements` paths without mounting the app
under an extra prefix.

## Things Not To Reintroduce

- Do not expose or store raw license keys beyond the one-time generated value;
  store hashes and last four characters.
- Do not store raw machine fingerprints; store SHA-256 hashes and last-eight
  support suffixes.
- Do not bypass device-limit checks for release manifests or download tokens.
- Do not make release download authorization depend only on `release_id`.
- Do not switch admin timestamp semantics away from ET display/input plus UTC
  storage/API output.
- Do not reintroduce product code assumptions that every Whop product maps to
  exactly one strategy.
- Do not treat NT8 lease tokens as public offline signatures.
- Do not put the Tradovate OAuth client secret in TraderPro Desktop or return it
  from any API.
- Do not store Tradovate OAuth state, codes, or tokens in plaintext; state is
  hashed and token material is encrypted.
- Do not add artifact upload handling to the admin UI unless the full storage,
  validation, and security model is designed.

## Documentation Maintenance Rule

When future work changes durable project knowledge, update the relevant
`docs/codex` note before finishing. Examples:

- new or removed endpoints
- schema migrations and persistent data semantics
- deployment host/path/unit/env changes
- security/authentication behavior
- client response contracts
- release targeting or package-mapping rules
- regression traps discovered while debugging
