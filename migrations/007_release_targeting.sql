ALTER TABLE customers ADD COLUMN tags_json TEXT DEFAULT '[]';

ALTER TABLE trader_releases ADD COLUMN audience_mode TEXT DEFAULT 'all';
ALTER TABLE trader_releases ADD COLUMN allowed_customer_ids_json TEXT DEFAULT '[]';
ALTER TABLE trader_releases ADD COLUMN allowed_emails_json TEXT DEFAULT '[]';
ALTER TABLE trader_releases ADD COLUMN allowed_license_key_hashes_json TEXT DEFAULT '[]';
ALTER TABLE trader_releases ADD COLUMN required_tags_json TEXT DEFAULT '[]';
ALTER TABLE trader_releases ADD COLUMN rollout_percent INTEGER DEFAULT 100;
ALTER TABLE trader_releases ADD COLUMN rollback_reason TEXT;

UPDATE customers
SET tags_json = '[]'
WHERE tags_json IS NULL;

UPDATE trader_releases
SET audience_mode = 'all'
WHERE audience_mode IS NULL;

UPDATE trader_releases
SET allowed_customer_ids_json = '[]'
WHERE allowed_customer_ids_json IS NULL;

UPDATE trader_releases
SET allowed_emails_json = '[]'
WHERE allowed_emails_json IS NULL;

UPDATE trader_releases
SET allowed_license_key_hashes_json = '[]'
WHERE allowed_license_key_hashes_json IS NULL;

UPDATE trader_releases
SET required_tags_json = '[]'
WHERE required_tags_json IS NULL;

UPDATE trader_releases
SET rollout_percent = 100
WHERE rollout_percent IS NULL;

CREATE INDEX IF NOT EXISTS idx_customers_tags
ON customers(tags_json);

CREATE INDEX IF NOT EXISTS idx_trader_releases_targeting_lookup
ON trader_releases(release_type, product_key, channel, platform, audience_mode, is_active, is_published, updated_at DESC);
