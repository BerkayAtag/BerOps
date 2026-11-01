DROP TABLE api_keys;
ALTER TABLE action_targets DROP COLUMN reboot_required;
DELETE FROM actions WHERE kind IN ('restart', 'collect_logs');
ALTER TABLE actions DROP COLUMN not_before;
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN ('deploy_package', 'run_command', 'deploy_patch'));
