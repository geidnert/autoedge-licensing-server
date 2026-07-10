ALTER TABLE entitlements
ADD COLUMN package_id TEXT REFERENCES whop_packages(id) ON DELETE SET NULL;

DROP INDEX IF EXISTS idx_entitlements_external;

CREATE UNIQUE INDEX idx_entitlements_external_source
ON entitlements(source, external_id, COALESCE(package_id, ''))
WHERE external_id IS NOT NULL;

UPDATE entitlements
SET package_id = (
    SELECT ledger.package_id
    FROM license_grant_ledger AS ledger
    WHERE ledger.entitlement_id = entitlements.id
      AND ledger.package_id IS NOT NULL
      AND ledger.grant_kind != 'ignored'
    ORDER BY ledger.applied_at DESC, ledger.rowid DESC
    LIMIT 1
)
WHERE source = 'whop'
  AND EXISTS (
      SELECT 1
      FROM license_grant_ledger AS ledger
      WHERE ledger.entitlement_id = entitlements.id
        AND ledger.package_id IS NOT NULL
        AND ledger.grant_kind != 'ignored'
  );

INSERT INTO entitlements(
    id, customer_id, product_id, subscription_id, package_id, external_id, source,
    status, starts_at, expires_at, revoked_at, manual_reason, whop_event_id,
    created_at, updated_at
)
SELECT
    lower(hex(randomblob(16))),
    entitlement.customer_id,
    entitlement.product_id,
    ledger.subscription_id,
    ledger.package_id,
    entitlement.external_id,
    entitlement.source,
    CASE ledger.grant_kind
        WHEN 'trial' THEN 'trialing'
        WHEN 'paid' THEN 'active'
        WHEN 'renewal' THEN 'active'
        WHEN 'revoke' THEN 'revoked'
        WHEN 'expire' THEN
            CASE
                WHEN ledger.expires_at_after IS NOT NULL
                 AND ledger.expires_at_after > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    THEN 'active'
                ELSE 'expired'
            END
        WHEN 'suspend' THEN 'suspended'
        ELSE entitlement.status
    END,
    entitlement.starts_at,
    ledger.expires_at_after,
    CASE WHEN ledger.grant_kind = 'revoke' THEN ledger.applied_at ELSE NULL END,
    entitlement.manual_reason,
    ledger.whop_event_id,
    entitlement.created_at,
    ledger.applied_at
FROM entitlements AS entitlement
JOIN license_grant_ledger AS ledger
  ON ledger.entitlement_id = entitlement.id
 AND ledger.package_id IS NOT NULL
 AND ledger.grant_kind != 'ignored'
WHERE entitlement.source = 'whop'
  AND ledger.id = (
      SELECT latest.id
      FROM license_grant_ledger AS latest
      WHERE latest.entitlement_id = entitlement.id
        AND latest.package_id = ledger.package_id
        AND latest.grant_kind != 'ignored'
      ORDER BY latest.applied_at DESC, latest.rowid DESC
      LIMIT 1
  )
  AND ledger.package_id != entitlement.package_id;

UPDATE entitlements
SET status = 'active',
    revoked_at = NULL
WHERE source = 'whop'
  AND status = 'expired'
  AND revoked_at IS NULL
  AND expires_at IS NOT NULL
  AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now');

CREATE INDEX idx_entitlements_package
ON entitlements(package_id);
