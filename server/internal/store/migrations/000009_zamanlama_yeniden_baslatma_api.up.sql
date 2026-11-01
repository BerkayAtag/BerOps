-- Aşama 9: zamanlanmış başlatma, yeniden başlatma takibi, ajan logları ve API anahtarları.
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check
    CHECK (kind IN ('deploy_package', 'run_command', 'deploy_patch', 'restart', 'collect_logs'));
ALTER TABLE actions ADD COLUMN not_before timestamptz;
COMMENT ON COLUMN actions.not_before IS 'Doluysa işler bu zamandan önce ajana verilmez (zamanlanmış başlatma)';

ALTER TABLE action_targets ADD COLUMN reboot_required boolean NOT NULL DEFAULT false;
COMMENT ON COLUMN action_targets.reboot_required IS 'Kurulum başarılı ama yeniden başlatma bekliyor (çıkış kodu 3010/1641)';

CREATE TABLE api_keys (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text        NOT NULL,
    key_prefix   text        NOT NULL,
    key_hash     bytea       NOT NULL UNIQUE,
    role         text        NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    scope_ous    text[]      NOT NULL DEFAULT '{}',
    created_by   uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
COMMENT ON TABLE api_keys IS 'Dış sistemler için REST API anahtarları (yalnızca özet saklanır)';
