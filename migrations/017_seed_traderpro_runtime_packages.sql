-- Seed TraderPro runtime package products without creating release rows,
-- artifacts, Whop mappings, grants, or entitlements. Existing product IDs are
-- retained so all current entitlement and release foreign keys remain valid.

-- ORBO2 previously used package/feature identifiers containing "orbo2".
-- Rename that product in place when the desired identifiers are not already
-- owned by another row.
UPDATE products
SET slug = 'orbo-runtime',
    feature_id = 'strategy.orbo.runtime',
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE (slug = 'orbo2-runtime' OR feature_id = 'strategy.orbo2.runtime')
  AND NOT EXISTS (
      SELECT 1
      FROM products AS desired
      WHERE desired.id != products.id
        AND (
            desired.slug = 'orbo-runtime'
            OR desired.feature_id = 'strategy.orbo.runtime'
        )
  );

CREATE TEMP TABLE traderpro_runtime_package_seeds (
    slug TEXT NOT NULL,
    name TEXT NOT NULL,
    feature_id TEXT NOT NULL,
    nt8_strategy_key TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);

INSERT INTO traderpro_runtime_package_seeds(
    slug, name, feature_id, nt8_strategy_key, metadata_json
)
VALUES
    (
        'orbo-runtime',
        'ORBO2 Runtime',
        'strategy.orbo.runtime',
        'ORBO2',
        '{"entry_assembly":"Trader.Strategies.Orbo.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"2.0.2.1","release_type":"strategy_package","runtime_package_id":"orbo-runtime","seeded":true,"strategy_family":"ORBO2","strategy_id":"orbo","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
    ),
    (
        'orboib-runtime',
        'ORBO2ib Runtime',
        'strategy.orboib.runtime',
        'ORBOib',
        '{"entry_assembly":"Trader.Strategies.Orboib.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"2.0.0.8","release_type":"strategy_package","runtime_package_id":"orboib-runtime","seeded":true,"strategy_family":"ORBO2ib","strategy_id":"orboib","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
    ),
    (
        'adam-runtime',
        'ADAM Runtime',
        'strategy.adam.runtime',
        'ADAM',
        '{"entry_assembly":"Trader.Strategies.Adam.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"1.0.1.5","release_type":"strategy_package","runtime_package_id":"adam-runtime","seeded":true,"strategy_family":"ADAM","strategy_id":"adam","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
    ),
    (
        'eve-runtime',
        'EVE Runtime',
        'strategy.eve.runtime',
        'EVE',
        '{"entry_assembly":"Trader.Strategies.Eve.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"1.0.2.6","release_type":"strategy_package","runtime_package_id":"eve-runtime","seeded":true,"strategy_family":"EVE","strategy_id":"eve","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
    ),
    (
        'aura-runtime',
        'AURA Runtime',
        'strategy.aura.runtime',
        'AURA',
        '{"entry_assembly":"Trader.Strategies.Aura.dll","initial_runtime_version":"0.1.0","minimum_trader_version":"0.1.182","package_kind":"strategy_package","package_signature":{"algorithm":"Ed25519","key_id":"main-2026-01"},"planned_nt8_version":"1.0.0.3","release_type":"strategy_package","runtime_package_id":"aura-runtime","seeded":true,"strategy_family":"AURA","strategy_id":"aura","supported_platforms":["macos-arm64","windows-x64","linux-x64"],"variant":"Runtime"}'
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
FROM traderpro_runtime_package_seeds AS seed
WHERE NOT EXISTS (
    SELECT 1
    FROM products
    WHERE products.slug = seed.slug
       OR products.feature_id = seed.feature_id
);

UPDATE products
SET name = (
        SELECT seed.name
        FROM traderpro_runtime_package_seeds AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    slug = (
        SELECT seed.slug
        FROM traderpro_runtime_package_seeds AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    feature_id = (
        SELECT seed.feature_id
        FROM traderpro_runtime_package_seeds AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    is_active = 1,
    nt8_strategy_key = COALESCE(
        NULLIF(nt8_strategy_key, ''),
        (
            SELECT seed.nt8_strategy_key
            FROM traderpro_runtime_package_seeds AS seed
            WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
            LIMIT 1
        )
    ),
    trader_enabled = 1,
    nt8_enabled = 1,
    metadata_json = (
        SELECT seed.metadata_json
        FROM traderpro_runtime_package_seeds AS seed
        WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
        LIMIT 1
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE EXISTS (
    SELECT 1
    FROM traderpro_runtime_package_seeds AS seed
    WHERE seed.slug = products.slug OR seed.feature_id = products.feature_id
);

DROP TABLE traderpro_runtime_package_seeds;
