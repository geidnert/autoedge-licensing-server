ALTER TABLE trader_releases
ADD COLUMN nt8_version TEXT;

ALTER TABLE trader_releases
ADD COLUMN trader_revision INTEGER
CHECK (trader_revision IS NULL OR trader_revision >= 0);
