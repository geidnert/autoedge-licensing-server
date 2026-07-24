-- Keep private/internal products out of customer manifests unless the
-- requesting customer is both entitled and eligible for a visible release.
-- Existing products remain public by default when this metadata key is absent.

UPDATE products
SET metadata_json = json_set(
        CASE
            WHEN json_valid(metadata_json) THEN metadata_json
            ELSE '{}'
        END,
        '$.catalog_visibility',
        'private'
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE (
        id = '30eaa830cd3411d89cf4509d8a51ec8c'
        OR slug = 'emal-runtime'
        OR feature_id = 'strategy.emal.runtime'
    )
  AND COALESCE(
        json_extract(
            CASE
                WHEN json_valid(metadata_json) THEN metadata_json
                ELSE '{}'
            END,
            '$.catalog_visibility'
        ),
        'public'
      ) != 'private';
