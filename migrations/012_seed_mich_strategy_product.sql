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
    nt8_enabled
)
SELECT
    lower(hex(randomblob(16))),
    NULL,
    'mich-runtime',
    'MICH Runtime',
    'strategy.mich.runtime',
    1,
    '{"entry_assembly":"Trader.Strategies.Mich.dll","initial_runtime_version":"0.1.0","package_kind":"strategy_package","release_type":"strategy_package","runtime_package_id":"mich-runtime","seeded":true,"strategy_id":"mich","supported_platforms":["macos-arm64","windows-x64"]}',
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
    strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
    'MICH',
    1,
    1
WHERE NOT EXISTS (
    SELECT 1 FROM products WHERE slug = 'mich-runtime' OR feature_id = 'strategy.mich.runtime'
);

UPDATE products
SET name = 'MICH Runtime',
    slug = 'mich-runtime',
    feature_id = 'strategy.mich.runtime',
    is_active = 1,
    nt8_strategy_key = COALESCE(NULLIF(nt8_strategy_key, ''), 'MICH'),
    trader_enabled = 1,
    nt8_enabled = 1,
    metadata_json = CASE
        WHEN metadata_json IS NULL
          OR metadata_json = ''
          OR metadata_json = '{}'
          OR metadata_json = '{"package_kind": "strategy", "seeded": true}'
        THEN '{"entry_assembly":"Trader.Strategies.Mich.dll","initial_runtime_version":"0.1.0","package_kind":"strategy_package","release_type":"strategy_package","runtime_package_id":"mich-runtime","seeded":true,"strategy_id":"mich","supported_platforms":["macos-arm64","windows-x64"]}'
        ELSE metadata_json
    END,
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE slug = 'mich-runtime' OR feature_id = 'strategy.mich.runtime';
