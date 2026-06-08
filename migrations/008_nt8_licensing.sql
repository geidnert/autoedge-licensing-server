ALTER TABLE products ADD COLUMN nt8_strategy_key TEXT;
ALTER TABLE products ADD COLUMN trader_enabled INTEGER NOT NULL DEFAULT 1;
ALTER TABLE products ADD COLUMN nt8_enabled INTEGER NOT NULL DEFAULT 1;

UPDATE products
SET nt8_strategy_key = replace(replace(name, ' Runtime', ''), ' ', '')
WHERE nt8_strategy_key IS NULL OR nt8_strategy_key = '';

ALTER TABLE devices ADD COLUMN client_type TEXT NOT NULL DEFAULT 'trader_desktop';
ALTER TABLE license_checks ADD COLUMN client_type TEXT NOT NULL DEFAULT 'trader_desktop';

CREATE INDEX IF NOT EXISTS idx_devices_customer_client
ON devices(customer_id, client_type, is_blocked, first_licensed_at);

CREATE INDEX IF NOT EXISTS idx_license_checks_customer_client_created
ON license_checks(customer_id, client_type, created_at DESC);
