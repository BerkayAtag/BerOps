-- Aşama 7: relay'ler, bakım pencereleri, kademeli dağıtım ve bildirimler.

CREATE TABLE relays (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text        NOT NULL,
    hostnames       text[]      NOT NULL,
    cert_serial     text        NOT NULL UNIQUE,
    cert_expires_at timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    last_ip         text        NOT NULL DEFAULT '',
    revoked_at      timestamptz
);
COMMENT ON TABLE relays IS 'Şube relay''leri; sertifika CN''si relay:<id>, seri numarası iptal kontrolü için';

CREATE TABLE maintenance_windows (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL,
    weekdays         smallint[]  NOT NULL CHECK (cardinality(weekdays) BETWEEN 1 AND 7),
    start_minute     smallint    NOT NULL CHECK (start_minute BETWEEN 0 AND 1439),
    duration_minutes integer     NOT NULL CHECK (duration_minutes BETWEEN 15 AND 1440),
    timezone         text        NOT NULL DEFAULT 'Europe/Istanbul',
    scope_ous        text[]      NOT NULL DEFAULT '{}',
    enabled          boolean     NOT NULL DEFAULT true,
    created_at       timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE maintenance_windows IS 'Bakım pencereleri; "pencereye uy" seçilen aksiyonlar yalnızca makinenin penceresi içinde verilir';
COMMENT ON COLUMN maintenance_windows.weekdays IS '0 = Pazar … 6 = Cumartesi';

ALTER TABLE actions ADD COLUMN respect_windows boolean NOT NULL DEFAULT false;
ALTER TABLE actions ADD COLUMN rollout jsonb;
ALTER TABLE actions ADD COLUMN paused_reason text NOT NULL DEFAULT '';
COMMENT ON COLUMN actions.rollout IS 'Kademeli dağıtım: {"stages":[{"percent":10,"delay_hours":0}, …], "min_success_percent":90}';

ALTER TABLE action_targets ADD COLUMN stage smallint NOT NULL DEFAULT 0;
ALTER TABLE action_targets ADD COLUMN released boolean NOT NULL DEFAULT true;
COMMENT ON COLUMN action_targets.released IS 'Kademeli dağıtımda hedefin aşaması açıldı mı';

CREATE TABLE notification_channels (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name       text        NOT NULL,
    kind       text        NOT NULL CHECK (kind IN ('email', 'webhook')),
    config     jsonb       NOT NULL,
    secret_enc bytea,
    events     text[]      NOT NULL DEFAULT '{}',
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_sent_at timestamptz,
    last_error text        NOT NULL DEFAULT ''
);
COMMENT ON COLUMN notification_channels.secret_enc IS 'SMTP parolası veya webhook imza anahtarı; AES-256-GCM şifreli';

CREATE TABLE notification_events (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event       text        NOT NULL,
    dedupe_key  text        NOT NULL,
    payload     jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (event, dedupe_key)
);
COMMENT ON TABLE notification_events IS 'Gönderilen olaylar; aynı olayın (ör. aynı KEV açığı) tekrar bildirilmesini önler';

CREATE TABLE report_schedules (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    report      text        NOT NULL CHECK (report IN ('compliance', 'vulnerabilities', 'missing-patches', 'apps')),
    format      text        NOT NULL CHECK (format IN ('pdf', 'xlsx', 'csv')),
    lang        text        NOT NULL DEFAULT 'tr' CHECK (lang IN ('tr', 'en')),
    weekday     smallint    CHECK (weekday BETWEEN 0 AND 6),
    hour        smallint    NOT NULL CHECK (hour BETWEEN 0 AND 23),
    timezone    text        NOT NULL DEFAULT 'Europe/Istanbul',
    channel_id  uuid        NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    enabled     boolean     NOT NULL DEFAULT true,
    last_run_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
COMMENT ON COLUMN report_schedules.weekday IS 'Boşsa her gün, doluysa haftanın o günü';
