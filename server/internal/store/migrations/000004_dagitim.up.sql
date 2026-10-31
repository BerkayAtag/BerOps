-- Aşama 4: paket kütüphanesi, aksiyonlar (paket dağıtımı ve komut çalıştırma), hedef başına
-- sonuçlar ve aktarım ayarları.

CREATE TABLE packages (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL,
    version          text        NOT NULL,
    publisher        text        NOT NULL DEFAULT '',
    platform         text        NOT NULL CHECK (platform IN ('windows', 'darwin')),
    description      text        NOT NULL DEFAULT '',
    installer        text        NOT NULL CHECK (installer IN ('msi', 'exe', 'pkg', 'dmg', 'file')),
    install_command  text        NOT NULL DEFAULT '',
    shell            text        NOT NULL DEFAULT '',
    success_codes    integer[]   NOT NULL DEFAULT '{0}',
    detect_name      text        NOT NULL DEFAULT '',
    file_name        text        NOT NULL,
    file_size        bigint      NOT NULL CHECK (file_size >= 0),
    file_sha256      text        NOT NULL CHECK (length(file_sha256) = 64),
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz
);
CREATE UNIQUE INDEX packages_name_version_key ON packages (platform, lower(name), version) WHERE deleted_at IS NULL;
CREATE INDEX packages_sha256_idx ON packages (file_sha256);
COMMENT ON TABLE packages IS 'Paket kütüphanesi; dosyalar data_dir/packages altında SHA-256 adıyla saklanır';
COMMENT ON COLUMN packages.detect_name IS 'Kurulu uygulama adı kalıbı; daha eski sürümü olan makineler "güncelleme gerekli" sayılır';

CREATE TABLE actions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text        NOT NULL,
    kind            text        NOT NULL CHECK (kind IN ('deploy_package', 'run_command')),
    package_id      uuid REFERENCES packages (id),
    shell           text        NOT NULL DEFAULT '',
    command         text        NOT NULL DEFAULT '',
    timeout_seconds integer     NOT NULL CHECK (timeout_seconds BETWEEN 30 AND 86400),
    bandwidth_kbps  integer     NOT NULL CHECK (bandwidth_kbps > 0),
    status          text        NOT NULL CHECK (status IN ('pending_approval', 'active', 'completed', 'cancelled', 'rejected')),
    target_count    integer     NOT NULL,
    created_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    created_by_name text        NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    expires_at      timestamptz NOT NULL,
    approved_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    approved_at     timestamptz,
    completed_at    timestamptz,
    CONSTRAINT actions_package_kind CHECK ((kind = 'deploy_package') = (package_id IS NOT NULL))
);
CREATE INDEX actions_created_at_idx ON actions (created_at DESC);
CREATE INDEX actions_status_idx ON actions (status);
COMMENT ON TABLE actions IS 'Paket dağıtımı ve komut çalıştırma aksiyonları';

CREATE TABLE action_targets (
    action_id   uuid        NOT NULL REFERENCES actions (id) ON DELETE CASCADE,
    machine_id  uuid        NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    status      text        NOT NULL CHECK (status IN ('pending', 'downloading', 'running', 'succeeded', 'failed', 'cancelled', 'expired')),
    payload     bytea       NOT NULL,
    signature   bytea       NOT NULL,
    exit_code   integer,
    stdout      text        NOT NULL DEFAULT '',
    stderr      text        NOT NULL DEFAULT '',
    error       text        NOT NULL DEFAULT '',
    started_at  timestamptz,
    finished_at timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (action_id, machine_id)
);
CREATE INDEX action_targets_machine_open_idx ON action_targets (machine_id)
    WHERE status IN ('pending', 'downloading', 'running');
COMMENT ON TABLE action_targets IS 'Aksiyon hedefleri; payload sunucunun aksiyon anahtarıyla imzalanmış iş tanımıdır';

CREATE TABLE transfer_settings (
    id                   smallint PRIMARY KEY CHECK (id = 1),
    per_client_kbps      integer     NOT NULL CHECK (per_client_kbps BETWEEN 64 AND 10000000),
    max_upload_mb        integer     NOT NULL CHECK (max_upload_mb BETWEEN 1 AND 102400),
    command_approval     boolean     NOT NULL DEFAULT false,
    default_expiry_hours integer     NOT NULL CHECK (default_expiry_hours BETWEEN 1 AND 720),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    updated_by           uuid REFERENCES users (id) ON DELETE SET NULL
);
COMMENT ON TABLE transfer_settings IS 'İstemci başına hız sınırı, yükleme sınırı ve dört göz onayı ayarları (tek satır)';
