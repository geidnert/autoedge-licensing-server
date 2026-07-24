-- Seed the EMAL TraderPro runtime package product without creating release
-- rows, artifacts, Whop mappings, grants, or entitlements. Match either the
-- canonical slug or feature so an existing internal product keeps its ID.

CREATE TEMP TABLE emal_runtime_package_seed (
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    feature_id TEXT NOT NULL,
    nt8_strategy_key TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

INSERT INTO emal_runtime_package_seed(
    slug, name, feature_id, nt8_strategy_key, metadata_json
)
VALUES (
    'emal-runtime',
    'EMAL Runtime',
    'strategy.emal.runtime',
    'EMAL',
    '{"entry_assembly":"Trader.Strategies.Emal.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"1.0.0.0","planned_trader_revision":0,"release_policy":{"allowed_audience_modes":["disabled","allowlist"],"allowed_channels":["internal","canary"]},"release_type":"strategy_package","runtime_package_id":"emal-runtime","seeded":true,"strategy_family":"EMAL","strategy_id":"emal","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
);

INSERT INTO products(
    id,
    whop_product_id,
    slug,
    name,
    feature_id,
    is_active,
    metadata_json,
    created_at,
    updated_at,
    nt8_strategy_key,
    trader_enabled,
    nt8_enabled,
    subscription_url
)
SELECT
    lower(hex(randomblob(16))),
    NULL,
    seed.slug,
    seed.name,
    seed.feature_id,
    1,
    seed.metadata_json,
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
    seed.nt8_strategy_key,
    1,
    1,
    NULL
FROM emal_runtime_package_seed AS seed
WHERE NOT EXISTS (
    SELECT 1
    FROM products
    WHERE products.slug = seed.slug
       OR products.feature_id = seed.feature_id
);

UPDATE products
SET name = (
        SELECT seed.name
        FROM emal_runtime_package_seed AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    slug = (
        SELECT seed.slug
        FROM emal_runtime_package_seed AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    feature_id = (
        SELECT seed.feature_id
        FROM emal_runtime_package_seed AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    is_active = 1,
    nt8_strategy_key = COALESCE(
        NULLIF(nt8_strategy_key, ''),
        (
            SELECT seed.nt8_strategy_key
            FROM emal_runtime_package_seed AS seed
            WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
            LIMIT 1
        )
    ),
    trader_enabled = 1,
    nt8_enabled = 1,
    metadata_json = (
        SELECT seed.metadata_json
        FROM emal_runtime_package_seed AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE EXISTS (
    SELECT 1
    FROM emal_runtime_package_seed AS seed
    WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
);

DROP TABLE emal_runtime_package_seed;
