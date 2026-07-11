UPDATE products
SET metadata_json = replace(
        replace(
            metadata_json,
            '"supported_platforms":["macos-arm64","windows-x64"]',
            '"supported_platforms":["macos-arm64","windows-x64","linux-x64"]'
        ),
        '"supported_platforms": ["macos-arm64", "windows-x64"]',
        '"supported_platforms": ["macos-arm64", "windows-x64", "linux-x64"]'
    ),
    updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
WHERE (slug = 'mich-runtime' OR feature_id = 'strategy.mich.runtime')
  AND metadata_json IS NOT NULL
  AND metadata_json LIKE '%"supported_platforms"%'
  AND metadata_json NOT LIKE '%linux-x64%'
  AND (
      metadata_json LIKE '%"supported_platforms":["macos-arm64","windows-x64"]%'
      OR metadata_json LIKE '%"supported_platforms": ["macos-arm64", "windows-x64"]%'
  );
