ALTER TABLE trader_releases ADD COLUMN release_type TEXT;
ALTER TABLE trader_releases ADD COLUMN product_key TEXT;
ALTER TABLE trader_releases ADD COLUMN is_published INTEGER;
ALTER TABLE trader_releases ADD COLUMN published_at TEXT;
ALTER TABLE trader_releases ADD COLUMN signature_key_id TEXT;

UPDATE trader_releases
SET release_type = CASE
        WHEN scope = 'app' THEN 'trader_desktop'
        ELSE 'strategy_package'
    END,
    product_key = CASE
        WHEN scope = 'app' THEN 'trader-desktop'
        ELSE (
            SELECT products.slug
            FROM products
            WHERE products.id = trader_releases.product_id
        )
    END,
    is_published = is_active,
    published_at = CASE
        WHEN is_active = 1 THEN created_at
        ELSE NULL
    END
WHERE release_type IS NULL;

CREATE INDEX IF NOT EXISTS idx_trader_releases_type_lookup
ON trader_releases(release_type, product_key, channel, platform, is_published, created_at DESC);
