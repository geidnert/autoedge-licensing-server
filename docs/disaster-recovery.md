# AutoEdge Disaster Recovery

This runbook covers two different failures:

1. the development/Codex computer is lost while production is still running;
2. the production Debian host is lost and must be rebuilt.

GitHub is the source of truth for code and operational instructions. It is not
the storage location for customer data, release artifacts, credentials, SSH
keys, or private signing keys.

## Recovery inventory

| Asset | Authoritative recovery source | In GitHub? |
| --- | --- | --- |
| Application, migrations, tests, pinned Python packages | This repository | Yes |
| Codex instructions and durable project memory | `AGENTS.md`, `docs/codex/` | Yes |
| nginx/Caddy and systemd service templates | `deploy/`, `systemd/` | Yes |
| Production SQLite customer/licensing data | Encrypted off-host restic snapshots | No |
| Production release artifacts | Encrypted off-host restic snapshots | No |
| Production environment/secrets | Encrypted off-host restic snapshots plus external password manager | No |
| Online TraderPro license-signing private key | Encrypted production snapshot | No |
| Offline release-signing private key | Separate encrypted off-host key snapshot | No |
| GitHub, server, DNS, Whop, Tradovate, and backup account recovery | External password manager with working 2FA recovery | No |
| SSH private keys | Secure credential backup or replacement through account/provider recovery | No |

The current offline release key is normally stored outside repositories at
`~/.config/autoedge/signing/release-2026-01-private.pem`. Its public fingerprint
is `b7057a866d42ebe0e0e14ef108a2103ccca68540b29503ab16deedece8fdd87c`.
Never put the private PEM in Git, chat, a deployment archive, or the production
server.

## Required recovery guarantees

- Completed repository work is committed and pushed before a Codex task ends.
- GitHub Actions runs the full unit suite on pushes and pull requests.
- Production receives an encrypted off-host backup every day.
- Keep at least 7 daily, 5 weekly, and 12 monthly production snapshots.
- The restic repository password and storage-account recovery information exist
  in an external password manager or recovery vault accessible from a new
  computer.
- The offline release-signing key has its own encrypted off-host snapshot.
- At least quarterly, restore both backup types into an isolated temporary
  location and verify them. A backup that has never been restored is unproven.

With the daily timer, the intended production recovery point objective is at
most 24 hours. Completed source work has a recovery point of the latest
successful GitHub push.

## New development computer

Prerequisites:

- access to the GitHub account and its 2FA recovery method;
- Git, Python 3.11 or newer, and Codex;
- a new or restored SSH key authorized for GitHub;
- server SSH access, or access to the hosting provider console so a new SSH key
  can be authorized; and
- the external password-manager/recovery-vault entry described above.

Clone and bootstrap:

```bash
git clone git@github.com:geidnert/autoedge-licensing-server.git
cd autoedge-licensing-server
./scripts/bootstrap_development.sh
./scripts/check_recovery_readiness.sh
```

The bootstrap script creates `.venv`, installs `requirements.txt`, creates the
ignored local `.env` and artifact directory, and runs all tests. Production
secrets are not needed for normal code/test work and must not be copied into the
repository.

Restore the offline release key only when release signing is needed. Restore it
from the separate encrypted key snapshot, set its private-file permission to
`0600`, and verify its public fingerprint:

```bash
AUTOEDGE_ES256_PUBLIC_KEY_PATH="$HOME/.config/autoedge/signing/release-2026-01-public.pem" \
  .venv/bin/python scripts/es256_keys.py fingerprint
```

The result must match the fingerprint in the inventory above. Sign and verify a
non-production fixture before using the restored key for a release.

## Configure encrypted off-host production backups

The repository uses [restic](https://restic.net/) because it encrypts snapshots,
deduplicates the 22+ GB artifact tree, supports off-host backends, retention,
integrity checks, and isolated restores. The supported commands are documented
in restic's official [backup](https://restic.readthedocs.io/en/stable/040_backup.html),
[restore](https://restic.readthedocs.io/en/stable/050_restore.html), and
[snapshot removal](https://restic.readthedocs.io/en/stable/060_forget.html)
guides.

Choose a storage backend physically independent of the production VPS and the
development computer, for example a restricted S3-compatible bucket, Backblaze
B2 bucket, or a separate SFTP backup host. Do not use a directory on the
production VPS as the only restic repository.

On production:

```bash
sudo apt update
sudo apt install -y restic
sudo install -d -o root -g root -m 0700 \
  /var/backups/autoedge-licensing/current /var/cache/autoedge-restic
sudo install -o root -g root -m 0600 \
  /opt/autoedge-licensing/deploy/autoedge-backup.env.example \
  /etc/autoedge-backup.env
sudo sh -c 'umask 077; openssl rand -base64 48 > /etc/autoedge-restic-password'
sudo editor /etc/autoedge-backup.env
```

Store the exact contents of `/etc/autoedge-restic-password`, the backend
credentials, repository URL, and provider recovery details in the external
password manager. Do this before initializing the repository. Losing the
repository password loses the encrypted backups.

After `/etc/autoedge-backup.env` contains the selected backend:

```bash
sudo bash -c 'set -a; . /etc/autoedge-backup.env; set +a; restic init'
sudo install -o root -g root -m 0644 \
  /opt/autoedge-licensing/systemd/autoedge-backup.service \
  /etc/systemd/system/autoedge-backup.service
sudo install -o root -g root -m 0644 \
  /opt/autoedge-licensing/systemd/autoedge-backup.timer \
  /etc/systemd/system/autoedge-backup.timer
sudo systemctl daemon-reload
sudo systemctl enable --now autoedge-backup.timer
sudo systemctl start autoedge-backup.service
sudo systemctl status autoedge-backup.service
sudo systemctl list-timers autoedge-backup.timer
```

`scripts/backup_sqlite.py` uses SQLite's online backup API and verifies
`PRAGMA quick_check` before restic runs. The production snapshot includes:

- the consistent SQLite snapshot;
- the release artifact tree;
- `/etc/autoedge-licensing.env`;
- `/etc/autoedge-licensing/` including the online license-signing key and
  release public verification key;
- installed systemd/nginx configuration; and
- the deployed source tree without its replaceable virtual environment.

The backup script then applies retention and runs `restic check`. Review failures
with:

```bash
sudo systemctl status autoedge-backup.service
sudo journalctl -u autoedge-backup.service
```

## Back up the offline release-signing key

Use a separate restic repository or credentials with a narrower access policy
than production when possible. Install restic on the release workstation,
configure `RESTIC_REPOSITORY` and `RESTIC_PASSWORD_FILE`, and store their
recovery details outside the workstation. Then run:

```bash
./scripts/backup_release_signing_key.sh \
  "$HOME/.config/autoedge/signing/release-2026-01-private.pem" \
  "$HOME/.config/autoedge/signing/release-2026-01-public.pem"
```

Confirm the snapshot from a second machine or isolated account. The production
backup deliberately cannot replace this step because the offline release
private key must never be put on the licensing server.

## Quarterly recovery test

On an isolated machine with enough free storage:

```bash
restic snapshots --tag autoedge-production
restic check --read-data-subset=5%
restic restore SNAPSHOT_ID --target /srv/autoedge-restore-test
python3 -c 'import sqlite3; print(sqlite3.connect("/srv/autoedge-restore-test/var/backups/autoedge-licensing/current/autoedge.db").execute("PRAGMA quick_check").fetchone()[0])'
```

The result must be `ok`. Confirm that the restored snapshot contains the
environment file, online license keypair, release public key, artifacts, and
systemd/nginx configuration. Audit the restored active artifact inventory with
`scripts/audit_release_artifacts.py` in an isolated checkout configured to use
the restored database and artifacts.

Separately restore the `autoedge-offline-release-key` snapshot, verify the
public fingerprint, sign a non-production envelope, verify it with the public
key, then securely delete the test restore.

Record the test date, snapshot IDs, database quick-check result, artifact audit
result, and key fingerprint in `docs/codex/project-memory.md`. Do not record
passwords, credentials, or private-key material.

## Rebuild a lost production host

1. Provision Debian with Python 3.11+, nginx or Caddy, Git, and restic.
2. Restore GitHub access and clone this repository.
3. Follow `README.md` through the Debian service-user, directory, virtualenv,
   systemd, and reverse-proxy setup, but do not create a fresh production admin
   or seed a replacement database.
4. Configure restic from the external recovery vault and select the latest
   verified `autoedge-production` snapshot:

```bash
restic snapshots --tag autoedge-production
restic restore SNAPSHOT_ID --target /srv/autoedge-restore
```

5. Stop the service. Restore the database, artifacts, environment file, online
   signing keys, release public keys, and relevant nginx/systemd files from the
   isolated restore tree. Preserve the owners and modes documented in
   `README.md` and `docs/codex/project-memory.md`.
6. Ensure `/opt/autoedge-licensing` is `root:root 0755`, recreate `.venv`, and
   install `requirements.txt`.
7. Before starting the service, run `PRAGMA quick_check` on the restored
   database and audit active release artifacts.
8. Start the service and verify:

```bash
sudo systemctl start autoedge-licensing
sudo systemctl is-active autoedge-licensing
curl -fsS http://127.0.0.1:8788/healthz
curl -fsS https://solidparts.se/privacy
curl -fsS https://solidparts.se/admin/login >/dev/null
```

9. Restore or update DNS, TLS, the Whop webhook URL/secret, and the Tradovate
   redirect URI if the public IP or hostname changed.
10. Install and run the backup timer on the replacement host immediately.

Do not overwrite a running host directly from a restore. Always restore into an
isolated directory, inspect it, stop the service, and only then copy the
selected files into their final locations.

## Before every completed Codex task

Run relevant tests, then:

```bash
git status --branch --short
git push
./scripts/check_recovery_readiness.sh
```

The readiness check must report a clean tree and a branch matching its upstream.
Use `--check-production-backup` with the production restic variables and
`--check-release-key-backup` with the key repository variables. Run them as
separate invocations when the two backup classes use separate repositories.
Never solve a readiness failure by committing secrets, databases, artifacts, or
private keys.
