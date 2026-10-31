-- Aşama 1: kullanıcılar, oturumlar, kayıt anahtarları, makineler ve denetim kaydı.
-- PostgreSQL 14+ (gen_random_uuid yerleşiktir).

CREATE TABLE users (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username        text        NOT NULL,
    display_name    text        NOT NULL DEFAULT '',
    source          text        NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'ad')),
    password_hash   text,
    role            text        NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    is_recovery     boolean     NOT NULL DEFAULT false,
    totp_secret_enc bytea,
    disabled        boolean     NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_login_at   timestamptz,
    CONSTRAINT users_local_has_password CHECK (source <> 'local' OR password_hash IS NOT NULL)
);
CREATE UNIQUE INDEX users_username_key ON users (lower(username));
COMMENT ON TABLE users IS 'Konsol kullanıcıları (yerel ve AD)';
COMMENT ON COLUMN users.is_recovery IS 'AD erişilemezken kullanılan yerel kurtarma admin hesabı';
COMMENT ON COLUMN users.totp_secret_enc IS 'Şifrelenmiş TOTP gizli anahtarı (Aşama 5)';

CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY,
    user_id      uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token   text        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    ip           text        NOT NULL DEFAULT '',
    user_agent   text        NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
COMMENT ON TABLE sessions IS 'Konsol oturumları; yalnızca token özeti saklanır';

CREATE TABLE registration_keys (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name             text        NOT NULL,
    key_hash         bytea       NOT NULL UNIQUE,
    key_prefix       text        NOT NULL,
    require_approval boolean     NOT NULL DEFAULT false,
    max_uses         integer CHECK (max_uses IS NULL OR max_uses > 0),
    use_count        integer     NOT NULL DEFAULT 0,
    expires_at       timestamptz,
    revoked_at       timestamptz,
    created_by       uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE registration_keys IS 'Ajan kayıt anahtarları; düz metin saklanmaz';

CREATE TABLE machines (
    id                  uuid PRIMARY KEY,
    hostname            text        NOT NULL,
    status              text        NOT NULL CHECK (status IN ('active', 'pending', 'rejected', 'revoked')),
    os_platform         text        NOT NULL CHECK (os_platform IN ('windows', 'darwin')),
    os_name             text        NOT NULL DEFAULT '',
    os_version          text        NOT NULL DEFAULT '',
    os_build            text        NOT NULL DEFAULT '',
    arch                text        NOT NULL DEFAULT '',
    ip_addresses        text[]      NOT NULL DEFAULT '{}',
    agent_version       text        NOT NULL DEFAULT '',
    ad_ou               text        NOT NULL DEFAULT '',
    cert_serial         text        NOT NULL,
    cert_fingerprint    text        NOT NULL,
    cert_expires_at     timestamptz NOT NULL,
    registration_key_id uuid REFERENCES registration_keys (id) ON DELETE SET NULL,
    enrolled_at         timestamptz NOT NULL DEFAULT now(),
    last_seen_at        timestamptz,
    agent_started_at    timestamptz,
    last_errors         text[]      NOT NULL DEFAULT '{}'
);
CREATE INDEX machines_hostname_idx ON machines (lower(hostname));
CREATE INDEX machines_last_seen_at_idx ON machines (last_seen_at);
CREATE INDEX machines_status_idx ON machines (status);
COMMENT ON TABLE machines IS 'Kayıtlı ajanlar; id ajan sertifikasının CN değeridir';
COMMENT ON COLUMN machines.cert_serial IS 'Geçerli istemci sertifikasının seri numarası; farklı seri reddedilir';

CREATE TABLE audit_log (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_type  text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system', 'api_key')),
    actor_id    text        NOT NULL DEFAULT '',
    actor_name  text        NOT NULL DEFAULT '',
    action      text        NOT NULL,
    target_type text        NOT NULL DEFAULT '',
    target_id   text        NOT NULL DEFAULT '',
    params      jsonb       NOT NULL DEFAULT '{}',
    result      text        NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    detail      text        NOT NULL DEFAULT '',
    source_ip   text        NOT NULL DEFAULT ''
);
CREATE INDEX audit_log_occurred_at_idx ON audit_log (occurred_at DESC);
CREATE INDEX audit_log_action_idx ON audit_log (action);
CREATE INDEX audit_log_target_idx ON audit_log (target_type, target_id);
COMMENT ON TABLE audit_log IS 'Değiştirilemez denetim kaydı (yalnızca ekleme)';

CREATE FUNCTION audit_log_immutable() RETURNS trigger
    LANGUAGE plpgsql AS
$$
BEGIN
    RAISE EXCEPTION 'audit_log yalnızca eklemeye açıktır (% engellendi)', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER audit_log_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TRIGGER audit_log_no_truncate
    BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();
