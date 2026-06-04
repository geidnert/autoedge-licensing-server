CREATE TABLE IF NOT EXISTS whop_packages (
    id TEXT PRIMARY KEY,
    whop_id TEXT NOT NULL UNIQUE,
    whop_id_type TEXT NOT NULL DEFAULT 'plan',
    name TEXT NOT NULL,
    default_days INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    is_ignored INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (whop_id_type IN ('plan', 'product', 'unknown')),
    CHECK (default_days IS NULL OR default_days >= 0)
);

CREATE TABLE IF NOT EXISTS whop_package_grants (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES whop_packages(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    days INTEGER,
    legacy_nt_product_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (package_id, product_id),
    CHECK (days IS NULL OR days >= 0)
);

CREATE TABLE IF NOT EXISTS license_grant_ledger (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    package_id TEXT REFERENCES whop_packages(id) ON DELETE SET NULL,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(id) ON DELETE SET NULL,
    entitlement_id TEXT REFERENCES entitlements(id) ON DELETE SET NULL,
    whop_event_id TEXT NOT NULL,
    event_fingerprint TEXT NOT NULL UNIQUE,
    grant_kind TEXT NOT NULL,
    days_applied INTEGER NOT NULL DEFAULT 0,
    period_start TEXT,
    period_end TEXT,
    expires_at_before TEXT,
    expires_at_after TEXT,
    details_json TEXT,
    applied_at TEXT NOT NULL,
    CHECK (grant_kind IN ('trial', 'paid', 'renewal', 'revoke', 'expire', 'suspend', 'ignored'))
);

CREATE INDEX IF NOT EXISTS idx_whop_package_grants_package ON whop_package_grants(package_id);
CREATE INDEX IF NOT EXISTS idx_license_grant_ledger_customer ON license_grant_ledger(customer_id, applied_at DESC);
CREATE INDEX IF NOT EXISTS idx_license_grant_ledger_product ON license_grant_ledger(product_id, applied_at DESC);
