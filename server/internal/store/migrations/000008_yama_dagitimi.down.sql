DELETE FROM actions WHERE kind = 'deploy_patch';
ALTER TABLE actions DROP COLUMN patches;
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN ('deploy_package', 'run_command'));
