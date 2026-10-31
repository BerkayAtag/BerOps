-- Aşama 3: CVE motoru (NVD, MSRC, CISA KEV, FIRST EPSS), makine zafiyetleri, risk özeti
-- ve günlük uyumluluk anlık görüntüleri.

CREATE TABLE cves (
    id             text PRIMARY KEY,
    source         text        NOT NULL CHECK (source IN ('nvd', 'msrc')),
    title          text        NOT NULL DEFAULT '',
    description    text        NOT NULL DEFAULT '',
    published_at   timestamptz,
    modified_at    timestamptz,
    cvss_score     real CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    cvss_vector    text        NOT NULL DEFAULT '',
    cvss_version   text        NOT NULL DEFAULT '',
    severity       text        NOT NULL DEFAULT '' CHECK (severity IN ('', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
    cwes           text[]      NOT NULL DEFAULT '{}',
    refs           text[]      NOT NULL DEFAULT '{}',
    msrc_exploited boolean     NOT NULL DEFAULT false,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE cves IS 'CVE kayıtları; NVD kaydı varsa CVSS ve açıklama NVD''den, başlık ve istismar bilgisi MSRC''den gelir';

CREATE TABLE cve_cpe_matches (
    cve_id                  text    NOT NULL REFERENCES cves (id) ON DELETE CASCADE,
    part                    char(1) NOT NULL CHECK (part IN ('a', 'o', 'h')),
    vendor                  text    NOT NULL,
    product                 text    NOT NULL,
    version                 text    NOT NULL DEFAULT '',
    version_start_including text    NOT NULL DEFAULT '',
    version_start_excluding text    NOT NULL DEFAULT '',
    version_end_including   text    NOT NULL DEFAULT '',
    version_end_excluding   text    NOT NULL DEFAULT ''
);
CREATE INDEX cve_cpe_matches_product_idx ON cve_cpe_matches (vendor, product);
CREATE INDEX cve_cpe_matches_cve_idx ON cve_cpe_matches (cve_id);
COMMENT ON TABLE cve_cpe_matches IS 'NVD yapılandırmalarındaki savunmasız CPE eşleşmeleri ve sürüm aralıkları';

CREATE TABLE msrc_remediations (
    cve_id       text NOT NULL REFERENCES cves (id) ON DELETE CASCADE,
    kb           text NOT NULL DEFAULT '',
    build_family text NOT NULL DEFAULT '',
    fixed_build  text NOT NULL DEFAULT '',
    severity     text NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, kb, build_family)
);
CREATE INDEX msrc_remediations_kb_idx ON msrc_remediations (kb) WHERE kb <> '';
CREATE INDEX msrc_remediations_family_idx ON msrc_remediations (build_family) WHERE build_family <> '';
COMMENT ON COLUMN msrc_remediations.build_family IS 'Windows yapı ailesi (ör. 10.0.22631); makinenin yapısı fixed_build''den küçükse savunmasızdır';

CREATE TABLE kev (
    cve_id          text PRIMARY KEY,
    vendor          text    NOT NULL DEFAULT '',
    product         text    NOT NULL DEFAULT '',
    name            text    NOT NULL DEFAULT '',
    date_added      date    NOT NULL,
    due_date        date,
    ransomware      boolean NOT NULL DEFAULT false,
    required_action text    NOT NULL DEFAULT ''
);
COMMENT ON TABLE kev IS 'CISA Known Exploited Vulnerabilities kataloğu';

CREATE TABLE epss (
    cve_id     text PRIMARY KEY,
    score      real NOT NULL,
    percentile real NOT NULL,
    scored_on  date NOT NULL
);
COMMENT ON TABLE epss IS 'FIRST EPSS istismar olasılığı skorları (0-1)';

CREATE TABLE feed_status (
    feed            text PRIMARY KEY CHECK (feed IN ('nvd', 'msrc', 'kev', 'epss')),
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    item_count      integer NOT NULL DEFAULT 0,
    duration_ms     bigint  NOT NULL DEFAULT 0,
    last_error      text    NOT NULL DEFAULT '',
    state           jsonb   NOT NULL DEFAULT '{}'
);
COMMENT ON COLUMN feed_status.state IS 'Artımlı eşitleme durumu (NVD son değişiklik zamanı, işlenen MSRC belgeleri)';

CREATE TABLE app_cpe_rules (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name_pattern       text        NOT NULL DEFAULT '',
    publisher_pattern  text        NOT NULL DEFAULT '',
    identifier_pattern text        NOT NULL DEFAULT '',
    part               char(1)     NOT NULL DEFAULT 'a' CHECK (part IN ('a', 'o')),
    vendor             text        NOT NULL,
    product            text        NOT NULL,
    created_by         uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT app_cpe_rules_has_pattern CHECK (name_pattern <> '' OR identifier_pattern <> '')
);
COMMENT ON TABLE app_cpe_rules IS 'Yerleşik sözlüğe ek olarak yöneticinin tanımladığı uygulama → CPE eşlemeleri';

CREATE TABLE machine_vulnerabilities (
    machine_id    uuid        NOT NULL REFERENCES machines (id) ON DELETE CASCADE,
    cve_id        text        NOT NULL,
    sources       text[]      NOT NULL,
    refs          text[]      NOT NULL DEFAULT '{}',
    fixed_by      text[]      NOT NULL DEFAULT '{}',
    risk_score    real        NOT NULL DEFAULT 0,
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    PRIMARY KEY (machine_id, cve_id)
);
CREATE INDEX machine_vulnerabilities_cve_idx ON machine_vulnerabilities (cve_id);
COMMENT ON TABLE machine_vulnerabilities IS 'Makine × CVE bulguları; kaynak: os_build, missing_patch veya app';

CREATE TABLE machine_risk (
    machine_id     uuid PRIMARY KEY REFERENCES machines (id) ON DELETE CASCADE,
    vuln_count     integer     NOT NULL DEFAULT 0,
    critical_count integer     NOT NULL DEFAULT 0,
    high_count     integer     NOT NULL DEFAULT 0,
    kev_count      integer     NOT NULL DEFAULT 0,
    max_risk       real        NOT NULL DEFAULT 0,
    computed_at    timestamptz NOT NULL
);
COMMENT ON TABLE machine_risk IS 'Makine başına zafiyet sayaçları ve en yüksek risk skoru';

CREATE TABLE compliance_snapshots (
    day               date PRIMARY KEY,
    machines          integer     NOT NULL,
    with_inventory    integer     NOT NULL,
    fully_patched     integer     NOT NULL,
    critical_machines integer     NOT NULL,
    kev_machines      integer     NOT NULL,
    vuln_total        integer     NOT NULL,
    avg_risk          real        NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);
COMMENT ON TABLE compliance_snapshots IS 'Gösterge panelindeki eğilim grafiği için günlük özet';
