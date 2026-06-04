DROP INDEX IF EXISTS idx_whop_package_grants_package;

ALTER TABLE whop_package_grants RENAME TO whop_package_grants_old;

CREATE TABLE whop_package_grants (
    id TEXT PRIMARY KEY,
    package_id TEXT NOT NULL REFERENCES whop_packages(id) ON DELETE CASCADE,
    product_id TEXT NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    days INTEGER,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (package_id, product_id),
    CHECK (days IS NULL OR days >= 0)
);

INSERT INTO whop_package_grants(id, package_id, product_id, days, created_at, updated_at)
SELECT id, package_id, product_id, days, created_at, updated_at
FROM whop_package_grants_old;

DROP TABLE whop_package_grants_old;

CREATE INDEX IF NOT EXISTS idx_whop_package_grants_package ON whop_package_grants(package_id);
