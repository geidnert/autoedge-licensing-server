# Codex Instructions

This repository is the AutoEdge licensing and entitlement server. It is a small
stdlib Python WSGI service backed by SQLite, with one pinned cryptographic
runtime dependency and no application framework.

## First Reads

- Read `docs/codex/project-memory.md` before making code or deployment changes.
- Read `README.md` for user-facing API, local development, deployment, and
  current production endpoint details.
- Check `git status --branch --short` before editing. The local `main` branch may
  intentionally be ahead of `origin/main`; do not rewrite or discard user work.

## Maintenance Rule

When future work changes durable project knowledge, update the relevant
`docs/codex` note before finishing. Durable knowledge includes architecture,
schema, endpoint contracts, deployment paths, operational workflows, security
assumptions, and regressions or gotchas that future Codex threads should not
rediscover.

## Continuity Rule

GitHub `origin` is the recovery source for code, tests, migrations, deployment
files, documentation, and Codex instructions. The repository owner has a
standing requirement that completed work must not remain only on one computer.

- Before finishing completed repository work, run the relevant verification,
  update durable documentation, commit the intended files, push the current
  branch, and confirm the branch is not ahead of its upstream.
- Do not commit unfinished experiments or unrelated user changes merely to make
  the tree clean. Preserve them and report them explicitly if they cannot be
  completed safely.
- Never commit `.env`, databases, artifacts, credentials, SSH keys, restic
  passwords/backend credentials, or private signing keys.
- When backup/recovery paths or required assets change, update
  `docs/disaster-recovery.md`, the backup configuration example, and the
  recovery readiness check in the same change.
- If a push or off-host backup check cannot be completed, say exactly what
  remains local before ending the task.

## Working Rules

- Do not change product code for repo-memory cleanup tasks unless it is required
  to make the docs accurate.
- Keep this service dependency-light. Do not add frameworks or package
  dependencies without a clear reason; the app is currently plain WSGI plus
  SQLite and `unittest`.
- Preserve security behavior: Whop Standard Webhooks verify the exact raw body,
  license keys and machine fingerprints are hashed, admin sessions are signed,
  and NT8 lease tokens use a server-side HMAC secret.
- Do not reintroduce legacy direct Whop product-only assumptions. Whop package
  mappings can grant one or more internal strategy products, and `plan_id` takes
  precedence over `product_id`.
- Keep client API blocking statuses explicit. Trader and NT8 clients rely on
  statuses such as `unknown_customer`, `unlicensed`, `expired`, `revoked`,
  `suspended`, `device_blocked`, `device_limit_exceeded`, `invalid_request`, and
  `rate_limited`.
- Admin time inputs and displays are US Eastern time (`ET`,
  `America/New_York`); persisted timestamps and API responses remain UTC `Z`.

## Verification

- Main test command: `python3 -m unittest discover -s tests`
- Local app command from `README.md`: set the required env vars, then run
  `python3 -m autoedge_licensing.app`.
- Scripts:
  - `python3 scripts/create_admin.py admin`
  - `python3 scripts/seed_products.py`
