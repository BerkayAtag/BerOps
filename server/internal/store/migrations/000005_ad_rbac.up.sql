-- Aşama 5: Active Directory (LDAPS) entegrasyonu, AD grubu → rol eşlemeleri ve OU kapsamlı yetki.

ALTER TABLE users ADD COLUMN scope_ous text[] NOT NULL DEFAULT '{}';
ALTER TABLE users ADD COLUMN ad_dn text NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN email text NOT NULL DEFAULT '';
COMMENT ON COLUMN users.scope_ous IS 'Kullanıcının görebileceği/yönetebileceği OU''lar; boşsa tüm makineler (admin rolünde yok sayılır)';

CREATE TABLE ad_settings (
    id                smallint PRIMARY KEY CHECK (id = 1),
    enabled           boolean     NOT NULL DEFAULT false,
    url               text        NOT NULL DEFAULT '',
    base_dn           text        NOT NULL DEFAULT '',
    bind_dn           text        NOT NULL DEFAULT '',
    bind_password_enc bytea,
    user_attr         text        NOT NULL DEFAULT 'sAMAccountName',
    user_filter       text        NOT NULL DEFAULT '(&(objectCategory=person)(objectClass=user))',
    ca_cert_pem       text        NOT NULL DEFAULT '',
    timeout_seconds   integer     NOT NULL DEFAULT 10 CHECK (timeout_seconds BETWEEN 2 AND 60),
    computers_base_dn text        NOT NULL DEFAULT '',
    updated_at        timestamptz NOT NULL DEFAULT now(),
    updated_by        uuid REFERENCES users (id) ON DELETE SET NULL
);
COMMENT ON COLUMN ad_settings.bind_password_enc IS 'Hizmet hesabı parolası; data_dir/pki/secret.key ile AES-256-GCM şifreli';

CREATE TABLE ad_group_roles (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    group_dn   text        NOT NULL,
    role       text        NOT NULL CHECK (role IN ('admin', 'technician', 'readonly')),
    scope_ous  text[]      NOT NULL DEFAULT '{}',
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX ad_group_roles_group_key ON ad_group_roles (lower(group_dn));
COMMENT ON TABLE ad_group_roles IS 'AD grubu → rol ve OU kapsamı eşlemeleri; kullanıcı her girişte gruplarına göre yeniden değerlendirilir';

CREATE INDEX audit_log_actor_idx ON audit_log (lower(actor_name));
CREATE INDEX machines_ad_ou_idx ON machines (lower(ad_ou));
