DROP TABLE agent_protection;
ALTER TABLE machines DROP COLUMN agent_capabilities;
ALTER TABLE machines DROP COLUMN prev_cert_serial;
DELETE FROM actions WHERE kind = 'update_agent';
ALTER TABLE actions DROP CONSTRAINT actions_package_kind;
ALTER TABLE actions ADD CONSTRAINT actions_package_kind CHECK ((kind = 'deploy_package') = (package_id IS NOT NULL));
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check
    CHECK (kind IN ('deploy_package', 'run_command', 'deploy_patch', 'restart', 'collect_logs'));
