package store

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// VulnListItem, filo genelindeki zafiyet listesinin satırıdır.
type VulnListItem struct {
	CVE              string     `json:"cve_id"`
	Title            string     `json:"title"`
	Severity         string     `json:"severity"`
	CVSS             *float32   `json:"cvss_score"`
	EPSS             *float32   `json:"epss"`
	EPSSPercentile   *float32   `json:"epss_percentile"`
	KEV              bool       `json:"kev"`
	KEVDue           *time.Time `json:"kev_due"`
	Ransomware       bool       `json:"ransomware"`
	Exploited        bool       `json:"exploited"`
	PublishedAt      *time.Time `json:"published_at"`
	AffectedMachines int        `json:"affected_machines"`
	Risk             float32    `json:"risk_score"`
	OS               bool       `json:"os"`  // işletim sistemi veya eksik yama kaynaklı
	App              bool       `json:"app"` // üçüncü parti uygulama kaynaklı
}

// VulnFilter, zafiyet listesi parametreleridir.
type VulnFilter struct {
	Search     string
	Severity   string // CRITICAL, HIGH, MEDIUM, LOW
	KEV        bool
	Kind       string // os, app
	MachineIDs []string
	Sort       string
	Desc       bool
	Limit      int
	Offset     int
	Unlimited  bool
}

// maxExportRows, rapor dışa aktarımındaki en fazla satırdır.
const maxExportRows = 200_000

// VulnSortColumns, izin verilen sıralama alanlarıdır.
var VulnSortColumns = map[string]string{
	"risk":      "a.risk",
	"cvss":      "c.cvss_score",
	"epss":      "e.score",
	"affected":  "a.affected",
	"published": "c.published_at",
	"cve":       "a.cve_id",
}

// activeMachine, zafiyet sayımlarında yalnızca aktif ve onay bekleyen makineleri alan koşuldur.
const activeMachine = `EXISTS (SELECT 1 FROM machines m WHERE m.id = mv.machine_id AND m.status IN ('active', 'pending'))`

// ListVulnerabilities, makinelerde bulunan CVE'leri etkilenen makine sayısı ve risk skoruyla döner.
func (s *Store) ListVulnerabilities(ctx context.Context, f VulnFilter) ([]VulnListItem, int, error) {
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	inner := []string{activeMachine}
	if len(f.MachineIDs) > 0 {
		inner = append(inner, "mv.machine_id = ANY("+arg(f.MachineIDs)+"::uuid[])")
	}
	var where []string
	if q := strings.TrimSpace(f.Search); q != "" {
		p := arg("%" + escapeLike(q) + "%")
		where = append(where, "(a.cve_id ILIKE "+p+" OR c.title ILIKE "+p+" OR c.description ILIKE "+p+")")
	}
	if f.Severity != "" {
		where = append(where, "c.severity = "+arg(f.Severity))
	}
	if f.KEV {
		where = append(where, "k.cve_id IS NOT NULL")
	}
	switch f.Kind {
	case "os":
		where = append(where, "a.os")
	case "app":
		where = append(where, "a.app")
	}
	cond := ""
	if len(where) > 0 {
		cond = "WHERE " + strings.Join(where, " AND ")
	}
	base := `
		WITH a AS (
			SELECT mv.cve_id, count(*) AS affected, max(mv.risk_score) AS risk,
			       bool_or(mv.sources && ARRAY['os_build', 'missing_patch', 'os']) AS os,
			       bool_or('app' = ANY(mv.sources)) AS app
			FROM machine_vulnerabilities mv WHERE ` + strings.Join(inner, " AND ") + `
			GROUP BY mv.cve_id
		)
		FROM a LEFT JOIN cves c ON c.id = a.cve_id
		LEFT JOIN epss e ON e.cve_id = a.cve_id
		LEFT JOIN kev k ON k.cve_id = a.cve_id ` + cond

	var total int
	if err := s.pool.QueryRow(ctx, strings.Replace(base, "FROM a LEFT", "SELECT count(*) FROM a LEFT", 1), args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	col, ok := VulnSortColumns[f.Sort]
	if !ok {
		col = VulnSortColumns["risk"]
	}
	dir := "DESC"
	if !f.Desc && f.Sort != "" {
		dir = "ASC"
	}
	limit := f.Limit
	if limit <= 0 || limit > 1000 {
		limit = 50
	}
	if f.Unlimited {
		limit = maxExportRows
	}
	q := strings.Replace(base, "FROM a LEFT", `SELECT a.cve_id, coalesce(nullif(c.title, ''), k.name, ''), coalesce(c.severity, ''), c.cvss_score,
		e.score, e.percentile, k.cve_id IS NOT NULL, k.due_date, coalesce(k.ransomware, false), coalesce(c.msrc_exploited, false),
		c.published_at, a.affected, a.risk, a.os, a.app FROM a LEFT`, 1) +
		` ORDER BY ` + col + ` ` + dir + ` NULLS LAST, a.affected DESC, a.cve_id DESC LIMIT ` + arg(limit) + ` OFFSET ` + arg(max(f.Offset, 0))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []VulnListItem{}
	for rows.Next() {
		var v VulnListItem
		if err := rows.Scan(&v.CVE, &v.Title, &v.Severity, &v.CVSS, &v.EPSS, &v.EPSSPercentile, &v.KEV, &v.KEVDue,
			&v.Ransomware, &v.Exploited, &v.PublishedAt, &v.AffectedMachines, &v.Risk, &v.OS, &v.App); err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// CVEDetail, tek bir CVE'nin ayrıntısıdır.
type CVEDetail struct {
	CVE            string        `json:"cve_id"`
	Known          bool          `json:"known"` // CVE veritabanında kayıtlı mı
	Source         string        `json:"source"`
	Title          string        `json:"title"`
	Description    string        `json:"description"`
	PublishedAt    *time.Time    `json:"published_at"`
	ModifiedAt     *time.Time    `json:"modified_at"`
	CVSS           *float32      `json:"cvss_score"`
	CVSSVector     string        `json:"cvss_vector"`
	CVSSVersion    string        `json:"cvss_version"`
	Severity       string        `json:"severity"`
	CWEs           []string      `json:"cwes"`
	Refs           []string      `json:"references"`
	Exploited      bool          `json:"exploited"`
	EPSS           *float32      `json:"epss"`
	EPSSPercentile *float32      `json:"epss_percentile"`
	KEV            *KEVInfo      `json:"kev"`
	Fixes          []string      `json:"fixes"` // KB'ler
	Affected       []AffectedRow `json:"affected"`
	Risk           float32       `json:"risk_score"`
}

// KEVInfo, CVE'nin KEV kaydıdır.
type KEVInfo struct {
	Name           string     `json:"name"`
	DateAdded      time.Time  `json:"date_added"`
	DueDate        *time.Time `json:"due_date"`
	Ransomware     bool       `json:"ransomware"`
	RequiredAction string     `json:"required_action"`
}

// AffectedRow, CVE'den etkilenen makinedir.
type AffectedRow struct {
	MachineID   string    `json:"machine_id"`
	Hostname    string    `json:"hostname"`
	Platform    string    `json:"os_platform"`
	OSName      string    `json:"os_name"`
	OSBuild     string    `json:"os_build"`
	Sources     []string  `json:"sources"`
	Refs        []string  `json:"refs"`
	FixedBy     []string  `json:"fixed_by"`
	FirstSeenAt time.Time `json:"first_seen_at"`
}

// GetCVEDetail, CVE ayrıntısını ve etkilenen makineleri (en fazla 1000) döner. CVE ne
// veritabanında ne de herhangi bir makinede yoksa ErrNotFound döner.
func (s *Store) GetCVEDetail(ctx context.Context, id string) (*CVEDetail, error) {
	d := &CVEDetail{CVE: id, CWEs: []string{}, Refs: []string{}, Fixes: []string{}, Affected: []AffectedRow{}}
	err := s.pool.QueryRow(ctx, `
		SELECT source, title, description, published_at, modified_at, cvss_score, cvss_vector, cvss_version,
		       severity, cwes, refs, msrc_exploited
		FROM cves WHERE id = $1`, id).Scan(&d.Source, &d.Title, &d.Description, &d.PublishedAt, &d.ModifiedAt,
		&d.CVSS, &d.CVSSVector, &d.CVSSVersion, &d.Severity, &d.CWEs, &d.Refs, &d.Exploited)
	switch err := notFound(err); err {
	case nil:
		d.Known = true
	case ErrNotFound:
	default:
		return nil, err
	}
	_ = s.pool.QueryRow(ctx, `SELECT score, percentile FROM epss WHERE cve_id = $1`, id).Scan(&d.EPSS, &d.EPSSPercentile)
	var k KEVInfo
	if err := s.pool.QueryRow(ctx, `SELECT name, date_added, due_date, ransomware, required_action FROM kev WHERE cve_id = $1`, id).
		Scan(&k.Name, &k.DateAdded, &k.DueDate, &k.Ransomware, &k.RequiredAction); err == nil {
		d.KEV = &k
		if d.Title == "" {
			d.Title = k.Name
		}
	}
	if err := s.pool.QueryRow(ctx, `SELECT coalesce(array_agg(DISTINCT kb ORDER BY kb), '{}') FROM msrc_remediations
		WHERE cve_id = $1 AND kb <> ''`, id).Scan(&d.Fixes); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT m.id, m.hostname, m.os_platform, m.os_name, m.os_build, mv.sources, mv.refs, mv.fixed_by,
		       mv.first_seen_at, mv.risk_score
		FROM machine_vulnerabilities mv JOIN machines m ON m.id = mv.machine_id
		WHERE mv.cve_id = $1 AND m.status IN ('active', 'pending')
		ORDER BY lower(m.hostname) LIMIT 1000`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a AffectedRow
		if err := rows.Scan(&a.MachineID, &a.Hostname, &a.Platform, &a.OSName, &a.OSBuild, &a.Sources, &a.Refs,
			&a.FixedBy, &a.FirstSeenAt, &d.Risk); err != nil {
			return nil, err
		}
		d.Affected = append(d.Affected, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !d.Known && len(d.Affected) == 0 {
		return nil, ErrNotFound
	}
	return d, nil
}

// MachineVuln, makine detayındaki zafiyet satırıdır.
type MachineVuln struct {
	CVE         string     `json:"cve_id"`
	Title       string     `json:"title"`
	Severity    string     `json:"severity"`
	CVSS        *float32   `json:"cvss_score"`
	EPSS        *float32   `json:"epss"`
	KEV         bool       `json:"kev"`
	Exploited   bool       `json:"exploited"`
	Sources     []string   `json:"sources"`
	Refs        []string   `json:"refs"`
	FixedBy     []string   `json:"fixed_by"`
	Risk        float32    `json:"risk_score"`
	FirstSeenAt time.Time  `json:"first_seen_at"`
	PublishedAt *time.Time `json:"published_at"`
}

// ListMachineVulns, makinenin bulgularını risk sırasıyla döner.
func (s *Store) ListMachineVulns(ctx context.Context, machineID string) ([]MachineVuln, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT mv.cve_id, coalesce(nullif(c.title, ''), k.name, ''), coalesce(c.severity, ''), c.cvss_score, e.score, k.cve_id IS NOT NULL,
		       coalesce(c.msrc_exploited, false), mv.sources, mv.refs, mv.fixed_by, mv.risk_score, mv.first_seen_at, c.published_at
		FROM machine_vulnerabilities mv
		LEFT JOIN cves c ON c.id = mv.cve_id
		LEFT JOIN epss e ON e.cve_id = mv.cve_id
		LEFT JOIN kev k ON k.cve_id = mv.cve_id
		WHERE mv.machine_id = $1
		ORDER BY mv.risk_score DESC, mv.cve_id DESC`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MachineVuln{}
	for rows.Next() {
		var v MachineVuln
		if err := rows.Scan(&v.CVE, &v.Title, &v.Severity, &v.CVSS, &v.EPSS, &v.KEV, &v.Exploited, &v.Sources, &v.Refs,
			&v.FixedBy, &v.Risk, &v.FirstSeenAt, &v.PublishedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// MachineRisk, makinenin risk özetidir.
type MachineRisk struct {
	VulnCount     int       `json:"vuln_count"`
	CriticalCount int       `json:"critical_count"`
	HighCount     int       `json:"high_count"`
	KEVCount      int       `json:"kev_count"`
	MaxRisk       float32   `json:"max_risk"`
	ComputedAt    time.Time `json:"computed_at"`
}

// GetMachineRisk, makinenin risk özetini döner.
func (s *Store) GetMachineRisk(ctx context.Context, machineID string) (*MachineRisk, error) {
	var r MachineRisk
	err := s.pool.QueryRow(ctx, `SELECT vuln_count, critical_count, high_count, kev_count, max_risk, computed_at
		FROM machine_risk WHERE machine_id = $1`, machineID).
		Scan(&r.VulnCount, &r.CriticalCount, &r.HighCount, &r.KEVCount, &r.MaxRisk, &r.ComputedAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

// RiskSummary, gösterge panelinin risk bölümüdür.
type RiskSummary struct {
	DistinctCVEs     int                `json:"distinct_cves"`
	AffectedMachines int                `json:"affected_machines"`
	KEVCVEs          int                `json:"kev_cves"`
	KEVMachines      int                `json:"kev_machines"`
	UrgentCVEs       int                `json:"urgent_cves"`
	AvgMachineRisk   float32            `json:"avg_machine_risk"`
	BySeverity       map[string]int     `json:"by_severity"`
	TopCVEs          []VulnListItem     `json:"top_cves"`
	TopMachines      []RiskyMachine     `json:"top_machines"`
	Trend            []ComplianceSample `json:"trend"`
}

// RiskyMachine, en riskli makineler listesinin satırıdır.
type RiskyMachine struct {
	ID            string  `json:"id"`
	Hostname      string  `json:"hostname"`
	Platform      string  `json:"os_platform"`
	VulnCount     int     `json:"vuln_count"`
	CriticalCount int     `json:"critical_count"`
	KEVCount      int     `json:"kev_count"`
	MaxRisk       float32 `json:"max_risk"`
}

// ComplianceSample, günlük uyumluluk özetidir.
type ComplianceSample struct {
	Day              string  `json:"day"`
	Machines         int     `json:"machines"`
	WithInventory    int     `json:"with_inventory"`
	FullyPatched     int     `json:"fully_patched"`
	CriticalMachines int     `json:"critical_machines"`
	KEVMachines      int     `json:"kev_machines"`
	VulnTotal        int     `json:"vuln_total"`
	AvgRisk          float32 `json:"avg_risk"`
}

// GetRiskSummary, gösterge paneli risk özetini hesaplar.
func (s *Store) GetRiskSummary(ctx context.Context, trendDays int) (*RiskSummary, error) {
	r := &RiskSummary{BySeverity: map[string]int{}, TopMachines: []RiskyMachine{}, Trend: []ComplianceSample{}}
	err := s.pool.QueryRow(ctx, `
		WITH mv AS (SELECT mv.* FROM machine_vulnerabilities mv WHERE `+activeMachine+`)
		SELECT count(DISTINCT mv.cve_id), count(DISTINCT mv.machine_id),
		       count(DISTINCT mv.cve_id) FILTER (WHERE k.cve_id IS NOT NULL),
		       count(DISTINCT mv.machine_id) FILTER (WHERE k.cve_id IS NOT NULL),
		       count(DISTINCT mv.cve_id) FILTER (WHERE mv.risk_score >= 80)
		FROM mv LEFT JOIN kev k ON k.cve_id = mv.cve_id`).
		Scan(&r.DistinctCVEs, &r.AffectedMachines, &r.KEVCVEs, &r.KEVMachines, &r.UrgentCVEs)
	if err != nil {
		return nil, err
	}
	if err := s.pool.QueryRow(ctx, `
		SELECT coalesce(avg(coalesce(r.max_risk, 0)), 0)
		FROM machines m JOIN machine_inventory i ON i.machine_id = m.id
		LEFT JOIN machine_risk r ON r.machine_id = m.id
		WHERE m.status IN ('active', 'pending')`).Scan(&r.AvgMachineRisk); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT coalesce(nullif(c.severity, ''), 'UNKNOWN'), count(DISTINCT mv.cve_id)
		FROM machine_vulnerabilities mv LEFT JOIN cves c ON c.id = mv.cve_id
		WHERE `+activeMachine+` GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, err
		}
		r.BySeverity[sev] = n
	}
	rows.Close()
	if r.TopCVEs, _, err = s.ListVulnerabilities(ctx, VulnFilter{Sort: "risk", Desc: true, Limit: 5}); err != nil {
		return nil, err
	}
	rows, err = s.pool.Query(ctx, `
		SELECT m.id, m.hostname, m.os_platform, r.vuln_count, r.critical_count, r.kev_count, r.max_risk
		FROM machine_risk r JOIN machines m ON m.id = r.machine_id
		WHERE m.status IN ('active', 'pending') AND r.vuln_count > 0
		ORDER BY r.max_risk DESC, r.kev_count DESC, r.vuln_count DESC, lower(m.hostname) LIMIT 5`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m RiskyMachine
		if err := rows.Scan(&m.ID, &m.Hostname, &m.Platform, &m.VulnCount, &m.CriticalCount, &m.KEVCount, &m.MaxRisk); err != nil {
			rows.Close()
			return nil, err
		}
		r.TopMachines = append(r.TopMachines, m)
	}
	rows.Close()
	if r.Trend, err = s.ListComplianceSnapshots(ctx, trendDays); err != nil {
		return nil, err
	}
	return r, nil
}

// SaveComplianceSnapshot, günün uyumluluk özetini yazar (aynı gün tekrar çağrılırsa günceller).
func (s *Store) SaveComplianceSnapshot(ctx context.Context, day time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO compliance_snapshots (day, machines, with_inventory, fully_patched, critical_machines, kev_machines,
			vuln_total, avg_risk)
		SELECT $1::date, count(*), count(i.machine_id),
		       count(*) FILTER (WHERE i.machine_id IS NOT NULL AND i.missing_count = 0 AND i.missing_scanned_at IS NOT NULL),
		       count(*) FILTER (WHERE i.missing_critical_count > 0 OR coalesce(r.critical_count, 0) > 0),
		       count(*) FILTER (WHERE coalesce(r.kev_count, 0) > 0),
		       coalesce(sum(r.vuln_count), 0),
		       coalesce(avg(coalesce(r.max_risk, 0)) FILTER (WHERE i.machine_id IS NOT NULL), 0)
		FROM machines m LEFT JOIN machine_inventory i ON i.machine_id = m.id
		LEFT JOIN machine_risk r ON r.machine_id = m.id
		WHERE m.status IN ('active', 'pending')
		ON CONFLICT (day) DO UPDATE SET machines = EXCLUDED.machines, with_inventory = EXCLUDED.with_inventory,
			fully_patched = EXCLUDED.fully_patched, critical_machines = EXCLUDED.critical_machines,
			kev_machines = EXCLUDED.kev_machines, vuln_total = EXCLUDED.vuln_total, avg_risk = EXCLUDED.avg_risk,
			created_at = now()`, day.UTC().Format(time.DateOnly))
	return err
}

// ListComplianceSnapshots, son n günün özetlerini eskiden yeniye döner.
func (s *Store) ListComplianceSnapshots(ctx context.Context, days int) ([]ComplianceSample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT to_char(day, 'YYYY-MM-DD'), machines, with_inventory, fully_patched, critical_machines, kev_machines,
		       vuln_total, avg_risk
		FROM (SELECT * FROM compliance_snapshots ORDER BY day DESC LIMIT $1) x ORDER BY day`, days)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ComplianceSample{}
	for rows.Next() {
		var c ComplianceSample
		if err := rows.Scan(&c.Day, &c.Machines, &c.WithInventory, &c.FullyPatched, &c.CriticalMachines,
			&c.KEVMachines, &c.VulnTotal, &c.AvgRisk); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MissingPatchReportRow, eksik yama raporunun satırıdır.
type MissingPatchReportRow struct {
	Hostname       string
	Platform       string
	OSBuild        string
	KB             string
	Version        string
	Title          string
	Classification string
	Severity       string
	ReleasedAt     *time.Time
	RebootRequired bool
	CVECount       int
}

// ReportMissingPatches, aktif makinelerdeki tüm eksik yamaları döner.
func (s *Store) ReportMissingPatches(ctx context.Context, platform, severity string) ([]MissingPatchReportRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT m.hostname, m.os_platform, m.os_build, p.kb, p.version, p.title, p.classification, p.severity,
		       p.released_at, p.reboot_required, cardinality(p.cves)
		FROM missing_patches p JOIN machines m ON m.id = p.machine_id
		WHERE m.status IN ('active', 'pending') AND ($1 = '' OR m.os_platform = $1) AND ($2 = '' OR p.severity = $2)
		ORDER BY lower(m.hostname), CASE p.severity WHEN 'Critical' THEN 0 WHEN 'Important' THEN 1
			WHEN 'Moderate' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, p.title
		LIMIT $3`, platform, severity, maxExportRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MissingPatchReportRow
	for rows.Next() {
		var r MissingPatchReportRow
		if err := rows.Scan(&r.Hostname, &r.Platform, &r.OSBuild, &r.KB, &r.Version, &r.Title, &r.Classification,
			&r.Severity, &r.ReleasedAt, &r.RebootRequired, &r.CVECount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AppReportRow, uygulama envanteri raporunun satırıdır.
type AppReportRow struct {
	Name      string
	Version   string
	Publisher string
	Platform  string
	Machines  int
}

// ReportApps, aktif makinelerdeki uygulamaları ad, sürüm ve platforma göre gruplayıp döner.
func (s *Store) ReportApps(ctx context.Context, platform, search string) ([]AppReportRow, error) {
	pattern := ""
	if q := strings.TrimSpace(search); q != "" {
		pattern = "%" + escapeLike(q) + "%"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT a.name, a.version, max(a.publisher), m.os_platform, count(DISTINCT a.machine_id)
		FROM installed_apps a JOIN machines m ON m.id = a.machine_id
		WHERE m.status IN ('active', 'pending') AND ($1 = '' OR m.os_platform = $1)
		  AND ($2 = '' OR a.name ILIKE $2 OR a.publisher ILIKE $2)
		GROUP BY a.name, a.version, m.os_platform
		ORDER BY lower(a.name), a.version, m.os_platform
		LIMIT $3`, platform, pattern, maxExportRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppReportRow
	for rows.Next() {
		var r AppReportRow
		if err := rows.Scan(&r.Name, &r.Version, &r.Publisher, &r.Platform, &r.Machines); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
