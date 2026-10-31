-- Aşama 6: isteğe bağlı (opt-in) uzaktan yönetim: performans, servisler, kayıt defteri.

CREATE TABLE remote_settings (
    id              smallint PRIMARY KEY CHECK (id = 1),
    enabled         boolean     NOT NULL DEFAULT false,
    session_minutes integer     NOT NULL DEFAULT 10 CHECK (session_minutes BETWEEN 1 AND 120),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    updated_by      uuid REFERENCES users (id) ON DELETE SET NULL
);
COMMENT ON TABLE remote_settings IS 'Uzaktan yönetimin genel ana anahtarı; kapalıyken makine ayarları yok sayılır';

CREATE TABLE machine_remote (
    machine_id     uuid PRIMARY KEY REFERENCES machines (id) ON DELETE CASCADE,
    performance    boolean     NOT NULL DEFAULT false,
    services       boolean     NOT NULL DEFAULT false,
    registry_read  boolean     NOT NULL DEFAULT false,
    registry_write boolean     NOT NULL DEFAULT false,
    updated_at     timestamptz NOT NULL DEFAULT now(),
    updated_by     uuid REFERENCES users (id) ON DELETE SET NULL
);
COMMENT ON TABLE machine_remote IS 'Makine başına açık uzaktan yönetim özellikleri (varsayılan hepsi kapalı)';
