-- Aşama 8: işletim sistemi yaması dağıtımı (deploy_patch).
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check CHECK (kind IN ('deploy_package', 'run_command', 'deploy_patch'));
ALTER TABLE actions ADD COLUMN patches text[] NOT NULL DEFAULT '{}';
COMMENT ON COLUMN actions.patches IS 'deploy_patch için kurulacak güncellemeler (Windows UpdateID / macOS etiketi)';
