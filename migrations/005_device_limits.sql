ALTER TABLE customers ADD COLUMN max_devices INTEGER;

ALTER TABLE devices ADD COLUMN first_licensed_at TEXT;
ALTER TABLE devices ADD COLUMN last_licensed_at TEXT;

UPDATE devices
SET first_licensed_at = (
        SELECT MIN(license_checks.created_at)
        FROM license_checks
        WHERE license_checks.device_id = devices.id
          AND license_checks.status = 'active'
    ),
    last_licensed_at = (
        SELECT MAX(license_checks.created_at)
        FROM license_checks
        WHERE license_checks.device_id = devices.id
          AND license_checks.status = 'active'
    )
WHERE EXISTS (
    SELECT 1
    FROM license_checks
    WHERE license_checks.device_id = devices.id
      AND license_checks.status = 'active'
);

CREATE INDEX IF NOT EXISTS idx_devices_customer_licensed ON devices(customer_id, is_blocked, first_licensed_at);
