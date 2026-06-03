CREATE TABLE IF NOT EXISTS customers (
    id TEXT PRIMARY KEY,
    whop_user_id TEXT UNIQUE,
    whop_member_id TEXT UNIQUE,
    email TEXT,
    email_normalized TEXT UNIQUE,
    name TEXT,
    license_key_hash TEXT UNIQUE,
    license_key_last4 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    whop_product_id TEXT UNIQUE,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    feature_id TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS subscriptions (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    whop_membership_id TEXT UNIQUE,
    whop_plan_id TEXT,
    status TEXT NOT NULL,
    raw_status TEXT,
    current_period_start TEXT,
    current_period_end TEXT,
    cancel_at_period_end INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (status IN ('active', 'trialing', 'past_due', 'expired', 'revoked', 'suspended', 'unknown'))
);

CREATE TABLE IF NOT EXISTS entitlements (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    subscription_id TEXT REFERENCES subscriptions(id) ON DELETE SET NULL,
    external_id TEXT,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    starts_at TEXT,
    expires_at TEXT,
    revoked_at TEXT,
    manual_reason TEXT,
    whop_event_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (source IN ('whop', 'manual')),
    CHECK (status IN ('active', 'trialing', 'expired', 'revoked', 'suspended', 'pending'))
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    fingerprint_hash TEXT NOT NULL,
    fingerprint_last8 TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    app_version TEXT,
    ip_last TEXT,
    user_agent_last TEXT,
    is_blocked INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    UNIQUE (customer_id, fingerprint_hash)
);

CREATE TABLE IF NOT EXISTS license_checks (
    id TEXT PRIMARY KEY,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    request_identifier TEXT,
    app_version TEXT,
    ip_address TEXT,
    user_agent TEXT,
    status TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL,
    actor_id TEXT,
    action TEXT NOT NULL,
    entity_type TEXT,
    entity_id TEXT,
    details_json TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webhook_events (
    webhook_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    received_at TEXT NOT NULL,
    processed_at TEXT,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    signature_valid INTEGER NOT NULL DEFAULT 0,
    error TEXT
);

CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS admin_sessions (
    id TEXT PRIMARY KEY,
    admin_user_id TEXT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_customers_email ON customers(email_normalized);
CREATE INDEX IF NOT EXISTS idx_entitlements_customer ON entitlements(customer_id);
CREATE INDEX IF NOT EXISTS idx_entitlements_product ON entitlements(product_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_entitlements_external ON entitlements(source, external_id) WHERE external_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_subscriptions_customer ON subscriptions(customer_id);
CREATE INDEX IF NOT EXISTS idx_devices_customer ON devices(customer_id);
CREATE INDEX IF NOT EXISTS idx_license_checks_customer_created ON license_checks(customer_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_entity_created ON audit_log(entity_type, entity_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token_hash);
