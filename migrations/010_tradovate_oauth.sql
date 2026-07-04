CREATE TABLE IF NOT EXISTS tradovate_oauth_states (
    state_hash TEXT PRIMARY KEY,
    state_last8 TEXT NOT NULL,
    status TEXT NOT NULL,
    environment TEXT NOT NULL,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    license_key_hash TEXT,
    email_normalized TEXT,
    whop_user_id TEXT,
    machine_fingerprint_hash TEXT NOT NULL,
    machine_fingerprint_last8 TEXT NOT NULL,
    app_version TEXT,
    platform TEXT,
    channel TEXT,
    authorization_url TEXT,
    tradovate_user_id TEXT,
    tradovate_user_name TEXT,
    tradovate_email TEXT,
    token_type TEXT,
    scopes TEXT,
    access_token_encrypted TEXT,
    refresh_token_encrypted TEXT,
    token_expires_at TEXT,
    failure_code TEXT,
    failure_message TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL,
    state_expires_at TEXT NOT NULL,
    completed_at TEXT,
    claimed_at TEXT,
    last_refreshed_at TEXT,
    CHECK (status IN ('pending', 'authorized', 'failed', 'expired')),
    CHECK (environment IN ('live', 'demo'))
);

CREATE INDEX IF NOT EXISTS idx_tradovate_oauth_state_status_expires
ON tradovate_oauth_states(status, state_expires_at);

CREATE INDEX IF NOT EXISTS idx_tradovate_oauth_customer_device_env
ON tradovate_oauth_states(customer_id, device_id, environment, created_at DESC);

