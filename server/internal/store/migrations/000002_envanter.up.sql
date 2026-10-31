-- Aşama 2: makine envanteri (işletim sistemi, kurulu/eksik yamalar, uygulamalar) ve ajan ayarları.

ALTER TABLE machines ADD COLUMN scan_requested_at timestamptz;
COMMENT ON COLUMN machines.scan_requested_at IS 'Konsoldan istenen yeniden tarama zamanı; sonraki heartbeat''te ajana iletilir';

CREATE TABLE machine_inventory (
    machine_id             uuid PRIMARY KEY REFERENCES machines (id) ON DELETE CASCADE,
    os                     jsonb,
    hashes                 jsonb       NOT NULL DEFAULT '{}',
    collected_at           timestamptz NOT NULL,
    received_at            timestamptz NOT NULL,
    last_full_at           timestamptz,
    scan_duration_ms       bigint      NOT NULL DEFAULT 0,
    missing_scan_source    text        NOT NULL DEFAULT '',
    missing_scanned_at     timestamptz,
    scan_errors            text[]      NOT NULL DEFAULT '{}',
    missing_count          integer     NOT NULL DEFAULT 0,
    missing_critical_count integer     NOT NULL DEFAULT 0,
    missing_security_count integer     NOT NULL DEFAULT 0,
    installed_patch_count  integer     NOT NULL DEFAULT 0,
    app_count              integer     NOT NULL DEFAULT 0,
    reboot_pending         boolean     NOT NULL DEFAULT false
);
COMMENT ON TABLE machine_inventory IS 'Makine başına envanter özeti; liste ekranları için sayaçlar burada tutulur';
COMMENT ON COLUMN machine_inventory.hashes IS 'Bölüm özetleri; ajanın bildirdiği özetlerle uyuşmazsa tam envanter istenir';

CREATE TABLE installed_patches (
    machine_id   uuid NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    patch_id     text NOT NULL,
    title        text NOT NULL DEFAULT '',
    installed_on date,
    source       text NOT NULL DEFAULT '',
    PRIMARY KEY (machine_id, patch_id)
);
CREATE INDEX installed_patches_patch_id_idx ON installed_patches (patch_id);
COMMENT ON TABLE installed_patches IS 'Kurulu yamalar (Windows KB, macOS güncellemeleri)';

CREATE TABLE missing_patches (
    machine_id      uuid    NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    update_id       text    NOT NULL,
    kb              text    NOT NULL DEFAULT '',
    title           text    NOT NULL,
    classification  text    NOT NULL DEFAULT '',
    severity        text    NOT NULL DEFAULT '',
    released_at     timestamptz,
    reboot_required boolean NOT NULL DEFAULT false,
    size_bytes      bigint  NOT NULL DEFAULT 0,
    cves            text[]  NOT NULL DEFAULT '{}',
    version         text    NOT NULL DEFAULT '',
    recommended     boolean NOT NULL DEFAULT false,
    support_url     text    NOT NULL DEFAULT '',
    PRIMARY KEY (machine_id, update_id)
);
CREATE INDEX missing_patches_update_id_idx ON missing_patches (update_id);
CREATE INDEX missing_patches_kb_idx ON missing_patches (kb) WHERE kb <> '';
CREATE INDEX missing_patches_cves_idx ON missing_patches USING gin (cves);
COMMENT ON TABLE missing_patches IS 'Eksik güncellemeler (Windows Update Agent / softwareupdate sonuçları)';

CREATE TABLE installed_apps (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    machine_id       uuid NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    name             text NOT NULL,
    version          text NOT NULL DEFAULT '',
    publisher        text NOT NULL DEFAULT '',
    install_date     date,
    install_location text NOT NULL DEFAULT '',
    source           text NOT NULL,
    identifier       text NOT NULL DEFAULT '',
    arch             text NOT NULL DEFAULT '',
    scope            text NOT NULL DEFAULT ''
);
CREATE INDEX installed_apps_machine_id_idx ON installed_apps (machine_id);
CREATE INDEX installed_apps_name_idx ON installed_apps (lower(name));
COMMENT ON TABLE installed_apps IS 'Kurulu üçüncü parti uygulamalar';

CREATE TABLE agent_settings (
    id         smallint PRIMARY KEY CHECK (id = 1),
    settings   jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users (id) ON DELETE SET NULL
);
COMMENT ON TABLE agent_settings IS 'Tüm ajanlara heartbeat ile iletilen genel ayarlar (tek satır)';
