CREATE TABLE IF NOT EXISTS trader_releases (
    id TEXT PRIMARY KEY,
    product_id TEXT REFERENCES products(id) ON DELETE SET NULL,
    scope TEXT NOT NULL DEFAULT 'strategy',
    channel TEXT NOT NULL DEFAULT 'stable',
    platform TEXT NOT NULL DEFAULT 'windows-x64',
    version TEXT NOT NULL,
    min_supported_version TEXT,
    is_required INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    artifact_path TEXT NOT NULL,
    artifact_filename TEXT NOT NULL,
    size_bytes INTEGER,
    sha256 TEXT,
    signature TEXT,
    release_notes TEXT,
    created_by_admin_id TEXT REFERENCES admin_users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (scope IN ('app', 'strategy')),
    CHECK (scope = 'app' OR product_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS release_download_tokens (
    token_hash TEXT PRIMARY KEY,
    release_id TEXT NOT NULL REFERENCES trader_releases(id) ON DELETE CASCADE,
    customer_id TEXT NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS release_downloads (
    id TEXT PRIMARY KEY,
    release_id TEXT REFERENCES trader_releases(id) ON DELETE SET NULL,
    customer_id TEXT REFERENCES customers(id) ON DELETE SET NULL,
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    token_hash TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trader_releases_lookup ON trader_releases(scope, product_id, channel, platform, is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_release_download_tokens_release ON release_download_tokens(release_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_release_downloads_customer_created ON release_downloads(customer_id, created_at DESC);
