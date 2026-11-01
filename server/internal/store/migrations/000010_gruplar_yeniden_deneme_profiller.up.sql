-- Aşama 10: makine grupları ve etiketleri, otomatik yeniden deneme, transfer profilleri.

-- Sürüm dizgesindeki sayıları karşılaştırılabilir diziye çevirir ("120.0.6099.71" → {120,0,6099,71}).
-- Sayı içermeyen sürümler boş dizi olur.
CREATE FUNCTION berops_version_key(v text) RETURNS numeric[]
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT coalesce(array_agg(m[1]::numeric ORDER BY ord), '{}')
    FROM regexp_matches(coalesce(v, ''), '(\d+)', 'g') WITH ORDINALITY AS t(m, ord)
$$;

CREATE TABLE machine_groups (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL,
    description text        NOT NULL DEFAULT '',
    kind        text        NOT NULL CHECK (kind IN ('static', 'dynamic')),
    rule        jsonb,
    created_by  uuid        REFERENCES users (id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT machine_groups_rule CHECK ((kind = 'dynamic') = (rule IS NOT NULL))
);
CREATE UNIQUE INDEX machine_groups_name_idx ON machine_groups (lower(name));
COMMENT ON TABLE machine_groups IS 'Makine grupları: statik (üye listesi) veya dinamik (kural; OU, etiket, uygulama sürümü vb.)';

CREATE TABLE machine_group_members (
    group_id   uuid NOT NULL REFERENCES machine_groups (id) ON DELETE CASCADE,
    machine_id uuid NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, machine_id)
);

CREATE TABLE machine_tags (
    machine_id uuid NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    tag        text NOT NULL CHECK (tag ~ '^[[:alnum:]][[:alnum:] ._-]{0,39}$'),
    PRIMARY KEY (machine_id, tag)
);
CREATE INDEX machine_tags_tag_idx ON machine_tags (lower(tag));

-- Otomatik yeniden deneme: başarısız hedef, retry_count kadar retry_delay_minutes sonra yeniden verilir.
ALTER TABLE actions ADD COLUMN retry_count smallint NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 5);
ALTER TABLE actions ADD COLUMN retry_delay_minutes integer NOT NULL DEFAULT 30 CHECK (retry_delay_minutes BETWEEN 1 AND 1440);
ALTER TABLE action_targets ADD COLUMN attempts smallint NOT NULL DEFAULT 0;
ALTER TABLE action_targets ADD COLUMN next_attempt_at timestamptz;

-- Transfer profilleri: saat bazlı istemci sınırı, toplam sunucu çıkış sınırı.
ALTER TABLE transfer_settings ADD COLUMN total_kbps integer NOT NULL DEFAULT 0 CHECK (total_kbps >= 0);
ALTER TABLE transfer_settings ADD COLUMN profiles jsonb NOT NULL DEFAULT '[]';
COMMENT ON COLUMN transfer_settings.total_kbps IS 'Tüm indirmelerin toplam üst sınırı (0 = sınırsız)';
COMMENT ON COLUMN transfer_settings.profiles IS 'Saat bazlı istemci sınırları: [{weekdays, start_minute, end_minute, kbps}]';
