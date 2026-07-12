# TraderPro ES256 Protection

This service uses the audited `cryptography` package and ES256 (ECDSA P-256
with SHA-256) for two deliberately separate trust domains:

- The online TraderPro license key signs short-lived license leases. Its private
  PEM exists only on the licensing server.
- Offline release keys sign immutable release envelopes. Release private PEMs
  exist only on a protected release workstation or CI runner. The licensing
  server receives public PEMs only and never signs release artifacts.

The existing NT8 HMAC lease is unchanged.

## Compact token format

Both token families use three unpadded base64url segments:

```text
base64url(header JSON).base64url(payload JSON).base64url(signature)
```

JSON is emitted as UTF-8-compatible ASCII with sorted object keys and no
insignificant whitespace. The signature input is the exact ASCII bytes of the
first two encoded segments joined by `.`. The external ES256 signature is the
64-byte IEEE-P1363/JWS representation `R || S`, with each unsigned integer
left-padded to 32 bytes. It is not ASN.1 DER.

License headers are:

```json
{"alg":"ES256","kid":"license-2026-01","typ":"autoedge-license+jws"}
```

Release headers are:

```json
{"alg":"ES256","kid":"release-2026-01","typ":"autoedge-release+jws"}
```

A verifier must reject malformed/unpadded base64url, any algorithm other than
`ES256`, an unknown `kid`, the wrong `typ`, a signature not exactly 64 bytes,
an invalid signature, the wrong payload `kind`, and—for license leases—invalid
`iat`, `nbf`, or `exp` times. It must also validate the expected issuer,
audience, customer, device, fingerprint hash, and feature claims.

## TraderPro license lease contract

An active TraderPro response has a new additive field. Blocking and unsigned
transition responses use `null`; old clients can ignore the field.

```json
{
  "license_lease": {
    "token": "<compact ES256 token>",
    "key_id": "license-2026-01",
    "issued_at": "2026-07-12T12:00:00Z",
    "expires_at": "2026-07-15T12:00:00Z"
  }
}
```

The signed payload is exactly:

```json
{
  "v": 1,
  "kind": "autoedge.trader-license",
  "iss": "solidparts.se",
  "aud": "traderpro",
  "sub": "<customer id>",
  "device_id": "<device id>",
  "device_fingerprint_sha256": "<64 lowercase hex characters>",
  "features": [
    {"id": "strategy.duo.runtime", "exp": "2026-08-01T00:00:00Z"},
    {"id": "trader.notifications.discord", "exp": null}
  ],
  "iat": 1783857600,
  "nbf": 1783857600,
  "exp": 1784116800,
  "jti": "<cryptographically random identifier>"
}
```

Features are sorted by `id`. `device_fingerprint_sha256` is SHA-256 of the
trimmed submitted fingerprint, identical to the server's stored fingerprint
hash. Each finite feature expiry remains authoritative. The token expiry is the
earliest of the configured offline grace deadline and all finite feature
expiries. A Lifetime feature has `exp: null` but the containing token always has
a finite expiry.

Manifests retain their top-level compatibility shape and include the same lease
under `license.license_lease`.

## Release envelope contract

The release pipeline computes artifact size and SHA-256, writes this exact JSON
object, and signs it before database insertion:

```json
{
  "v": 1,
  "kind": "autoedge.release",
  "release_type": "strategy_package",
  "package_id": "duo-runtime",
  "feature_id": "strategy.duo.runtime",
  "channel": "stable",
  "platform": "windows-x64",
  "version": "1.2.3",
  "minimum_trader_version": "1.0.0",
  "filename": "DUO-1.2.3-windows-x64.zip",
  "size_bytes": 123456,
  "sha256": "<64 lowercase hex characters>"
}
```

Allowed `release_type` values remain `strategy_package`,
`extension_package`, and `trader_desktop`. Desktop uses package ID
`trader-desktop` and `feature_id: null`. The signature intentionally excludes
the database release ID, audience, rollout, notes, required flag, and artifact
storage path. It binds immutable artifact-selection metadata and the download
filename.

When a release is registered and its artifact exists, the server always
calculates the real size and SHA-256. Any supplied mismatch is rejected. A
supplied signature is always verified, even while signatures are optional; its
header `kid`, separate `signature_key_id`, signed claims, and registration
metadata must all match.

`AUTOEDGE_REQUIRE_RELEASE_SIGNATURES=false` is the migration default. It keeps
unsigned historical releases readable/downloadable and permits unsigned new
registrations. When set to `true`, a new or updated published row must carry a
valid signature; inactive draft rows and untouched historical rows are not
rewritten.

## Configuration

Production license signing:

```dotenv
AUTOEDGE_TRADER_LICENSE_SIGNING_PRIVATE_KEY_PATH=/etc/autoedge-licensing/keys/license-2026-01-private.pem
AUTOEDGE_TRADER_LICENSE_SIGNING_KEY_ID=license-2026-01
AUTOEDGE_TRADER_LICENSE_VERIFICATION_KEYS='{"license-2026-01":"/etc/autoedge-licensing/keys/license-2026-01-public.pem"}'
AUTOEDGE_TRADER_LICENSE_ISSUER=solidparts.se
AUTOEDGE_TRADER_LICENSE_AUDIENCE=traderpro
```

Release verification on the server:

```dotenv
AUTOEDGE_RELEASE_VERIFICATION_KEYS='{"release-2026-01":"/etc/autoedge-licensing/release-public/release-2026-01.pem"}'
AUTOEDGE_REQUIRE_RELEASE_SIGNATURES=true
```

An empty release mapping is `{}` during the unsigned transition. Key mappings
are JSON objects, which allow old and new public keys to coexist during
rotation. Private-key paths are filesystem configuration, never CLI arguments.
Production completed this transition on 2026-07-12: unsigned historical rows
were retained but made inactive/unpublished, and mandatory release signatures
were enabled.

## Key generation and secure provisioning

Generate the online license keypair in a protected staging location, without
printing private PEM material:

```bash
AUTOEDGE_ES256_PRIVATE_KEY_PATH=/secure/staging/license-2026-01-private.pem \
AUTOEDGE_ES256_PUBLIC_KEY_PATH=/secure/staging/license-2026-01-public.pem \
.venv/bin/python scripts/es256_keys.py generate
```

Provision only that online private key on production:

```bash
install -d -o root -g autoedge -m 0750 /etc/autoedge-licensing/keys
install -o root -g autoedge -m 0640 license-2026-01-private.pem \
  /etc/autoedge-licensing/keys/license-2026-01-private.pem
install -o root -g autoedge -m 0644 license-2026-01-public.pem \
  /etc/autoedge-licensing/keys/license-2026-01-public.pem
```

Generate release keypairs separately on the offline release workstation. Never
copy a release private PEM to the licensing server. Export or fingerprint a
public key with:

```bash
AUTOEDGE_ES256_PRIVATE_KEY_PATH=/secure/release/release-2026-01-private.pem \
AUTOEDGE_ES256_PUBLIC_KEY_PATH=/secure/release/release-2026-01-public.pem \
.venv/bin/python scripts/es256_keys.py export-public

AUTOEDGE_ES256_PUBLIC_KEY_PATH=/secure/release/release-2026-01-public.pem \
.venv/bin/python scripts/es256_keys.py fingerprint
```

The fingerprint is SHA-256 over DER SubjectPublicKeyInfo bytes.

## Release signing and audit workflow

After producing an artifact, create the exact envelope JSON above, then sign it
on the release workstation:

```bash
AUTOEDGE_RELEASE_SIGNING_PRIVATE_KEY_PATH=/secure/release/release-2026-01-private.pem \
AUTOEDGE_RELEASE_SIGNING_KEY_ID=release-2026-01 \
.venv/bin/python scripts/sign_release_envelope.py release-envelope.json \
  --output release-envelope.jws
```

Verify it wherever the release public-key mapping is configured:

```bash
AUTOEDGE_RELEASE_VERIFICATION_KEYS='{"release-2026-01":"/secure/release/release-2026-01-public.pem"}' \
.venv/bin/python scripts/verify_release_envelope.py release-envelope.jws
```

Paste/store the compact token as `signature` and its header key ID as
`signature_key_id` during release registration. Audit every active row against
the real artifact and configured public keys with:

```bash
set -a
. /etc/autoedge-licensing.env
set +a
/opt/autoedge-licensing/.venv/bin/python \
  /opt/autoedge-licensing/scripts/audit_release_artifacts.py
```

## Rotation, client pinning, recovery, and revocation

TraderPro clients should ship a key-ID-to-public-key allowlist, not one implicit
key. They must choose the pinned public key by `kid`; a server-supplied public
key is never sufficient trust. Add a new public key to clients and the server
mapping before switching the active private key/key ID. Keep the retired public
key pinned until every lease it signed has expired and upgraded clients are
deployed, then remove it.

Release-key rotation follows the same add/sign/retire order, but old public keys
must remain pinned and configured for as long as artifacts signed by them are
supported. Re-signing an artifact changes only signature metadata when the
immutable envelope remains identical; otherwise publish a new version.

Back up private keys separately from code and databases into encrypted,
access-controlled recovery storage. Test recovery by restoring into an isolated
host, checking the public fingerprint, and signing/verifying a non-production
fixture. Never place private PEMs in Git, deployment archives, database backups,
logs, tickets, or chat.

If an online license key is suspected compromised, remove its private PEM from
service, generate a new key ID, update server/client public mappings, restart,
and revoke the old key ID in the next client release. Existing leases remain
valid to clients that still trust the compromised key until their finite `exp`,
so shorten operational grace before a planned emergency rotation when
possible. If a release key is compromised, stop publishing with it, remove it
from registration verification for new work, publish/pin a replacement key,
audit supported artifacts, and replace affected artifacts/signatures through a
controlled release. Preserve evidence and do not silently relabel a changed
artifact under the same immutable signed metadata.
