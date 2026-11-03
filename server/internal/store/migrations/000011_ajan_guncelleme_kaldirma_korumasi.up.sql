-- Aşama 11: ajan güncellemesi ve kaldırma koruması.
ALTER TABLE actions DROP CONSTRAINT actions_kind_check;
ALTER TABLE actions ADD CONSTRAINT actions_kind_check
    CHECK (kind IN ('deploy_package', 'run_command', 'deploy_patch', 'restart', 'collect_logs', 'update_agent'));
ALTER TABLE actions DROP CONSTRAINT actions_package_kind;
ALTER TABLE actions ADD CONSTRAINT actions_package_kind
    CHECK ((kind IN ('deploy_package', 'update_agent')) = (package_id IS NOT NULL));

-- Ajanın bildirdiği isteğe bağlı iş türleri; eski ajanlara desteklemedikleri iş gönderilmez.
ALTER TABLE machines ADD COLUMN agent_capabilities text[] NOT NULL DEFAULT '{}';
-- Sertifika yenilemede önceki seri numarası, ajan yeni sertifikayı kaydedemezse kilitlenmesin
-- diye kendi süresi bitene kadar kabul edilir.
ALTER TABLE machines ADD COLUMN prev_cert_serial text;

CREATE TABLE agent_protection (
    id          smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled     boolean NOT NULL DEFAULT false,
    salt        bytea,
    hash        bytea,
    iterations  integer,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid REFERENCES users (id) ON DELETE SET NULL,
    CHECK (NOT enabled OR (length(salt) >= 16 AND length(hash) = 32 AND iterations >= 10000))
);
COMMENT ON TABLE agent_protection IS 'Kaldırma koruması (tek satır): kodun yalnızca tuzlu PBKDF2-SHA256 özeti saklanır';
