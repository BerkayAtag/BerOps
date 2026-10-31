package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/BerkayAtag/BerOps/server/internal/cve"
)

// --- Kaynak durumu ---

// FeedStatus, bir CVE kaynağının son eşitleme bilgisidir.
type FeedStatus struct {
	Feed          string     `json:"feed"`
	LastAttemptAt *time.Time `json:"last_attempt_at"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	ItemCount     int        `json:"item_count"`
	DurationMs    int64      `json:"duration_ms"`
	LastError     string     `json:"last_error"`
}

// LoadFeedState, kaynağın artımlı eşitleme durumunu v'ye çözer.
func (s *Store) LoadFeedState(ctx context.Context, feed string, v any) error {
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT state FROM feed_status WHERE feed = $1`, feed).Scan(&raw)
	if err != nil {
		return notFound(err)
	}
	return json.Unmarshal(raw, v)
}

// BeginFeed, eşitleme denemesinin başladığını kaydeder.
func (s *Store) BeginFeed(ctx context.Context, feed string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO feed_status (feed, last_attempt_at) VALUES ($1, $2)
		ON CONFLICT (feed) DO UPDATE SET last_attempt_at = EXCLUDED.last_attempt_at`, feed, at)
	return err
}

// FinishFeed, eşitlemenin sonucunu yazar. Hata olsa da durum (ör. tamamlanan NVD ürünleri)
// saklanır; böylece sonraki deneme kaldığı yerden devam eder.
func (s *Store) FinishFeed(ctx context.Context, feed string, at time.Time, count int, dur time.Duration, state any, syncErr error) error {
	var stateJSON []byte
	if state != nil {
		var err error
		if stateJSON, err = json.Marshal(state); err != nil {
			return err
		}
	}
	if syncErr != nil {
		msg := syncErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
		_, err := s.pool.Exec(ctx, `
			UPDATE feed_status SET last_error = $2, duration_ms = $3, state = coalesce($4, state) WHERE feed = $1`,
			feed, msg, dur.Milliseconds(), stateJSON)
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE feed_status SET last_success_at = $2, item_count = $3, duration_ms = $4, last_error = '',
			state = coalesce($5, state)
		WHERE feed = $1`, feed, at, count, dur.Milliseconds(), stateJSON)
	return err
}

// ListFeedStatus, tüm kaynakların durumunu sabit sırayla döner.
func (s *Store) ListFeedStatus(ctx context.Context) ([]FeedStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT feed, last_attempt_at, last_success_at, item_count, duration_ms, last_error FROM feed_status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byFeed := map[string]FeedStatus{}
	for rows.Next() {
		var f FeedStatus
		if err := rows.Scan(&f.Feed, &f.LastAttemptAt, &f.LastSuccessAt, &f.ItemCount, &f.DurationMs, &f.LastError); err != nil {
			return nil, err
		}
		byFeed[f.Feed] = f
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]FeedStatus, 0, len(cve.AllFeeds))
	for _, f := range cve.AllFeeds {
		st, ok := byFeed[f]
		if !ok {
			st = FeedStatus{Feed: f}
		}
		out = append(out, st)
	}
	return out, nil
}

// --- CVE kayıtları ---

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// UpsertRecords, NVD ve MSRC kayıtlarını yazar. NVD kaydı CVSS ve açıklama için esas alınır;
// MSRC kaydı başlığı, istismar bilgisini ve Windows düzeltmelerini ekler, CVSS'yi yalnızca
// NVD skoru yoksa doldurur.
func (s *Store) UpsertRecords(ctx context.Context, recs []cve.Record) error {
	if len(recs) == 0 {
		return nil
	}
	// Aynı CVE bir partide birden fazla kez gelebilir; sonuncusu geçerlidir.
	byID := make(map[string]int, len(recs))
	uniq := make([]cve.Record, 0, len(recs))
	for _, r := range recs {
		if i, ok := byID[r.ID+r.Source]; ok {
			uniq[i] = r
			continue
		}
		byID[r.ID+r.Source] = len(uniq)
		uniq = append(uniq, r)
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		b := &pgx.Batch{}
		var nvdIDs []string
		for _, r := range uniq {
			switch r.Source {
			case "nvd":
				nvdIDs = append(nvdIDs, r.ID)
				b.Queue(`
					INSERT INTO cves AS c (id, source, title, description, published_at, modified_at, cvss_score,
						cvss_vector, cvss_version, severity, cwes, refs, updated_at)
					VALUES ($1, 'nvd', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
					ON CONFLICT (id) DO UPDATE SET
						source = 'nvd',
						title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE c.title END,
						description = EXCLUDED.description,
						published_at = coalesce(EXCLUDED.published_at, c.published_at),
						modified_at = EXCLUDED.modified_at,
						cvss_score = coalesce(EXCLUDED.cvss_score, c.cvss_score),
						cvss_vector = CASE WHEN EXCLUDED.cvss_score IS NOT NULL THEN EXCLUDED.cvss_vector ELSE c.cvss_vector END,
						cvss_version = CASE WHEN EXCLUDED.cvss_score IS NOT NULL THEN EXCLUDED.cvss_version ELSE c.cvss_version END,
						severity = CASE WHEN EXCLUDED.severity <> '' THEN EXCLUDED.severity ELSE c.severity END,
						cwes = EXCLUDED.cwes, refs = EXCLUDED.refs, updated_at = now()`,
					r.ID, r.Title, r.Description, r.Published, r.Modified, r.CVSS, r.CVSSVector, r.CVSSVersion,
					r.Severity, nonNilStrings(r.CWEs), nonNilStrings(r.Refs))
			case "msrc":
				b.Queue(`
					INSERT INTO cves AS c (id, source, title, published_at, cvss_score, cvss_vector, cvss_version,
						severity, msrc_exploited, updated_at)
					VALUES ($1, 'msrc', $2, $3, $4, $5, $6, $7, $8, now())
					ON CONFLICT (id) DO UPDATE SET
						title = CASE WHEN EXCLUDED.title <> '' THEN EXCLUDED.title ELSE c.title END,
						published_at = coalesce(c.published_at, EXCLUDED.published_at),
						cvss_score = CASE WHEN c.source = 'msrc' OR c.cvss_score IS NULL
							THEN coalesce(EXCLUDED.cvss_score, c.cvss_score) ELSE c.cvss_score END,
						cvss_vector = CASE WHEN c.source = 'msrc' OR c.cvss_score IS NULL
							THEN EXCLUDED.cvss_vector ELSE c.cvss_vector END,
						cvss_version = CASE WHEN c.source = 'msrc' OR c.cvss_score IS NULL
							THEN EXCLUDED.cvss_version ELSE c.cvss_version END,
						severity = CASE WHEN c.severity = '' OR c.source = 'msrc' THEN EXCLUDED.severity ELSE c.severity END,
						msrc_exploited = c.msrc_exploited OR EXCLUDED.msrc_exploited,
						updated_at = now()`,
					r.ID, r.Title, r.Published, r.CVSS, r.CVSSVector, r.CVSSVersion, r.Severity, r.Exploited)
				for _, rm := range r.Remediations {
					b.Queue(`
						INSERT INTO msrc_remediations (cve_id, kb, build_family, fixed_build, severity)
						VALUES ($1, $2, $3, $4, $5)
						ON CONFLICT (cve_id, kb, build_family) DO UPDATE SET
							fixed_build = EXCLUDED.fixed_build, severity = EXCLUDED.severity`,
						r.ID, rm.KB, rm.BuildFamily, rm.FixedBuild, rm.Severity)
				}
			}
		}
		if err := tx.SendBatch(ctx, b).Close(); err != nil {
			return err
		}
		if len(nvdIDs) == 0 {
			return nil
		}
		// NVD yapılandırmaları kayıt bazında bütün olarak değişir.
		if _, err := tx.Exec(ctx, `DELETE FROM cve_cpe_matches WHERE cve_id = ANY($1)`, nvdIDs); err != nil {
			return err
		}
		var rows [][]any
		for _, r := range uniq {
			if r.Source != "nvd" {
				continue
			}
			for _, m := range r.Matches {
				rows = append(rows, []any{r.ID, m.Part, m.Vendor, m.Product, m.Range.Exact, m.Range.StartIncluding,
					m.Range.StartExcluding, m.Range.EndIncluding, m.Range.EndExcluding})
			}
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"cve_cpe_matches"}, []string{"cve_id", "part", "vendor", "product",
			"version", "version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding"},
			pgx.CopyFromRows(rows))
		return err
	})
}

// ExistingCVEs, veritabanında bulunan CVE kimliklerini döner.
func (s *Store) ExistingCVEs(ctx context.Context, ids []string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM cves WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// ReplaceKEV, KEV kataloğunu tamamen yeniler.
func (s *Store) ReplaceKEV(ctx context.Context, entries []cve.KEVEntry) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM kev`); err != nil {
			return err
		}
		seen := map[string]bool{}
		rows := make([][]any, 0, len(entries))
		for _, e := range entries {
			if seen[e.CVE] {
				continue
			}
			seen[e.CVE] = true
			rows = append(rows, []any{e.CVE, e.Vendor, e.Product, e.Name, e.DateAdded, e.DueDate, e.Ransomware, e.RequiredAction})
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"kev"},
			[]string{"cve_id", "vendor", "product", "name", "date_added", "due_date", "ransomware", "required_action"},
			pgx.CopyFromRows(rows))
		return err
	})
}

// ReplaceEPSS, EPSS skorlarını tamamen yeniler ve yazılan satır sayısını döner.
func (s *Store) ReplaceEPSS(ctx context.Context, scoredOn time.Time, load func(add func(cve.EPSSScore) error) error) (int, error) {
	var rows [][]any
	seen := map[string]bool{}
	if err := load(func(e cve.EPSSScore) error {
		if !seen[e.CVE] {
			seen[e.CVE] = true
			rows = append(rows, []any{e.CVE, e.Score, e.Percentile, scoredOn})
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, errors.New("EPSS verisi boş")
	}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM epss`); err != nil {
			return err
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"epss"}, []string{"cve_id", "score", "percentile", "scored_on"}, pgx.CopyFromRows(rows))
		return err
	})
	return len(rows), err
}

// --- Korelasyon erişimi (cve.Lookup) ---

// BuildFixes, Windows yapı ailesinin MSRC düzeltmelerini döner.
func (s *Store) BuildFixes(ctx context.Context, family string) ([]cve.BuildFix, error) {
	rows, err := s.pool.Query(ctx, `SELECT cve_id, kb, fixed_build FROM msrc_remediations WHERE build_family = $1`, family)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cve.BuildFix
	for rows.Next() {
		var f cve.BuildFix
		if err := rows.Scan(&f.CVE, &f.KB, &f.FixedBuild); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// KBCVEs, KB numaralarının kapattığı CVE'leri döner.
func (s *Store) KBCVEs(ctx context.Context, kbs []string) (map[string][]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT kb, array_agg(DISTINCT cve_id) FROM msrc_remediations WHERE kb = ANY($1) GROUP BY kb`, kbs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var kb string
		var ids []string
		if err := rows.Scan(&kb, &ids); err != nil {
			return nil, err
		}
		out[kb] = ids
	}
	return out, rows.Err()
}

// ProductMatches, "a:vendor:product" ürününün savunmasız sürüm aralıklarını döner.
func (s *Store) ProductMatches(ctx context.Context, key string) ([]cve.CPEMatch, error) {
	part, rest, _ := strings.Cut(key, ":")
	vendor, product, _ := strings.Cut(rest, ":")
	rows, err := s.pool.Query(ctx, `
		SELECT cve_id, version, version_start_including, version_start_excluding, version_end_including, version_end_excluding
		FROM cve_cpe_matches WHERE part = $1 AND vendor = $2 AND product = $3`, part, vendor, product)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []cve.CPEMatch
	for rows.Next() {
		var m cve.CPEMatch
		r := &m.Range
		if err := rows.Scan(&m.CVE, &r.Exact, &r.StartIncluding, &r.StartExcluding, &r.EndIncluding, &r.EndExcluding); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- Özel uygulama kuralları ---

// ListAppRules, yöneticinin tanımladığı uygulama → CPE kurallarını döner.
func (s *Store) ListAppRules(ctx context.Context) ([]cve.ProductRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name_pattern, publisher_pattern, identifier_pattern, part, vendor, product
		FROM app_cpe_rules ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []cve.ProductRule{}
	for rows.Next() {
		var r cve.ProductRule
		if err := rows.Scan(&r.ID, &r.Name, &r.Publisher, &r.Identifier, &r.Part, &r.Vendor, &r.Product); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateAppRule, özel kural ekler.
func (s *Store) CreateAppRule(ctx context.Context, r cve.ProductRule, userID string) (cve.ProductRule, error) {
	part := r.Part
	if part == "" {
		part = "a"
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_cpe_rules (name_pattern, publisher_pattern, identifier_pattern, part, vendor, product, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		r.Name, r.Publisher, r.Identifier, part, r.Vendor, r.Product, nullableUUID(userID)).Scan(&r.ID)
	r.Part = part
	return r, err
}

// DeleteAppRule, özel kuralı siler.
func (s *Store) DeleteAppRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM app_cpe_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func nullableUUID(id string) any {
	if id == "" {
		return nil
	}
	return id
}

// --- Makine bulguları ---

// VulnInput, makinenin korelasyon girdisini okur. Makinenin envanteri yoksa ErrNotFound döner.
func (s *Store) VulnInput(ctx context.Context, machineID string) (cve.MachineInput, error) {
	var in cve.MachineInput
	err := s.pool.QueryRow(ctx, `
		SELECT m.os_platform, coalesce(i.os->>'version', m.os_version), coalesce(nullif(i.os->>'build', ''), m.os_build)
		FROM machines m JOIN machine_inventory i ON i.machine_id = m.id WHERE m.id = $1`, machineID).
		Scan(&in.Platform, &in.OSVersion, &in.OSBuild)
	if err != nil {
		return in, notFound(err)
	}
	rows, err := s.pool.Query(ctx, `SELECT kb, cves FROM missing_patches WHERE machine_id = $1`, machineID)
	if err != nil {
		return in, err
	}
	for rows.Next() {
		var mp cve.MissingRef
		if err := rows.Scan(&mp.KB, &mp.CVEs); err != nil {
			rows.Close()
			return in, err
		}
		in.Missing = append(in.Missing, mp)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}
	rows, err = s.pool.Query(ctx, `SELECT name, version, publisher, identifier, source FROM installed_apps WHERE machine_id = $1`, machineID)
	if err != nil {
		return in, err
	}
	defer rows.Close()
	for rows.Next() {
		var a cve.AppRef
		if err := rows.Scan(&a.Name, &a.Version, &a.Publisher, &a.Identifier, &a.Source); err != nil {
			return in, err
		}
		in.Apps = append(in.Apps, a)
	}
	return in, rows.Err()
}

// CVEMeta, risk hesabı için CVE bilgilerini (CVSS, önem, EPSS, KEV) döner. Veritabanında
// kaydı olmayan CVE'ler sonuçta yer almaz.
func (s *Store) CVEMeta(ctx context.Context, ids []string) (map[string]cve.Meta, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT x.id, c.cvss_score, coalesce(c.severity, ''), e.score, k.cve_id IS NOT NULL,
		       coalesce(k.ransomware, false), coalesce(c.msrc_exploited, false)
		FROM unnest($1::text[]) AS x(id)
		LEFT JOIN cves c ON c.id = x.id
		LEFT JOIN epss e ON e.cve_id = x.id
		LEFT JOIN kev k ON k.cve_id = x.id
		WHERE c.id IS NOT NULL OR e.cve_id IS NOT NULL OR k.cve_id IS NOT NULL`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]cve.Meta, len(ids))
	for rows.Next() {
		var id string
		var m cve.Meta
		var score *float32
		var epss *float32
		if err := rows.Scan(&id, &score, &m.Severity, &epss, &m.KEV, &m.Ransomware, &m.Exploited); err != nil {
			return nil, err
		}
		if score != nil {
			v := round1(float64(*score))
			m.CVSS = &v
		}
		if epss != nil {
			v := float64(*epss)
			m.EPSS = &v
		}
		out[id] = m
	}
	return out, rows.Err()
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

// ScoredFinding, risk skoru hesaplanmış bulgudur.
type ScoredFinding struct {
	cve.Finding
	Risk     float64
	Severity string // CRITICAL, HIGH, MEDIUM, LOW veya boş
	KEV      bool
}

// SaveMachineFindings, makinenin bulgularını yeniler (ilk görülme zamanı korunur) ve risk
// özetini günceller.
func (s *Store) SaveMachineFindings(ctx context.Context, machineID string, findings []ScoredFinding, at time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `CREATE TEMP TABLE IF NOT EXISTS tmp_findings (
			cve_id text, sources text[], refs text[], fixed_by text[], risk_score real, severity text, kev boolean
		) ON COMMIT DELETE ROWS`); err != nil {
			return err
		}
		rows := make([][]any, len(findings))
		for i, f := range findings {
			rows[i] = []any{f.CVE, nonNilStrings(f.Sources), nonNilStrings(f.Refs), nonNilStrings(f.FixedBy), f.Risk, f.Severity, f.KEV}
		}
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"tmp_findings"},
			[]string{"cve_id", "sources", "refs", "fixed_by", "risk_score", "severity", "kev"}, pgx.CopyFromRows(rows)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM machine_vulnerabilities mv WHERE mv.machine_id = $1
			AND NOT EXISTS (SELECT 1 FROM tmp_findings t WHERE t.cve_id = mv.cve_id)`, machineID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO machine_vulnerabilities (machine_id, cve_id, sources, refs, fixed_by, risk_score, first_seen_at, last_seen_at)
			SELECT $1, cve_id, sources, refs, fixed_by, risk_score, $2, $2 FROM tmp_findings
			ON CONFLICT (machine_id, cve_id) DO UPDATE SET sources = EXCLUDED.sources, refs = EXCLUDED.refs,
				fixed_by = EXCLUDED.fixed_by, risk_score = EXCLUDED.risk_score, last_seen_at = EXCLUDED.last_seen_at`,
			machineID, at); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO machine_risk (machine_id, vuln_count, critical_count, high_count, kev_count, max_risk, computed_at)
			SELECT $1, count(*), count(*) FILTER (WHERE severity = 'CRITICAL'), count(*) FILTER (WHERE severity = 'HIGH'),
			       count(*) FILTER (WHERE kev), coalesce(max(risk_score), 0), $2
			FROM tmp_findings
			ON CONFLICT (machine_id) DO UPDATE SET vuln_count = EXCLUDED.vuln_count, critical_count = EXCLUDED.critical_count,
				high_count = EXCLUDED.high_count, kev_count = EXCLUDED.kev_count, max_risk = EXCLUDED.max_risk,
				computed_at = EXCLUDED.computed_at`, machineID, at)
		return err
	})
}

// InventoriedMachineIDs, envanteri olan aktif ve onay bekleyen makineleri döner.
func (s *Store) InventoriedMachineIDs(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT m.id FROM machines m JOIN machine_inventory i ON i.machine_id = m.id
		WHERE m.status IN ('active', 'pending') ORDER BY m.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
