DROP TABLE IF EXISTS agent_settings;
DROP TABLE IF EXISTS installed_apps;
DROP TABLE IF EXISTS missing_patches;
DROP TABLE IF EXISTS installed_patches;
DROP TABLE IF EXISTS machine_inventory;
ALTER TABLE machines DROP COLUMN IF EXISTS scan_requested_at;
