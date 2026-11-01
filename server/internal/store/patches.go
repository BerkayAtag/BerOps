package store

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// FleetPatch, filoda eksik olan bir güncellemedir (makine başına satırların özeti).
type FleetPatch struct {
	UpdateID       string     `json:"update_id"`
	KB             string     `json:"kb"`
	Title          string     `json:"title"`
	Classification string     `json:"classification"`
	Severity       string     `json:"severity"`
	Platform       string     `json:"platform"`
	ReleasedAt     *time.Time `json:"released_at"`
	RebootRequired bool       `json:"reboot_required"`
	CVECount       int        `json:"cve_count"`
	Machines       int        `json:"machines"`
}

// maxFleetPatches, yama listesinin üst sınırıdır.
const maxFleetPatches = 2000

// FleetMissingPatches, aktif makinelerdeki eksik güncellemeleri güncelleme kimliğine göre
// gruplar; önem derecesi ve etkilenen makine sayısına göre sıralar.
func (s *Store) FleetMissingPatches(ctx context.Context, platform, severity, search string, scope []string) ([]FleetPatch, error) {
	pattern := ""
	if q := strings.TrimSpace(search); q != "" {
		pattern = "%" + escapeLike(q) + "%"
	}
	args := []any{platform, severity, pattern, maxFleetPatches}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	sc := ""
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		sc = " AND " + c
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.update_id, max(p.kb), max(p.title), max(p.classification), max(p.severity), max(m.os_platform),
		       max(p.released_at), bool_or(p.reboot_required), max(cardinality(p.cves)), count(DISTINCT p.machine_id)
		FROM missing_patches p JOIN machines m ON m.id = p.machine_id
		WHERE m.status = 'active' AND ($1 = '' OR m.os_platform = $1) AND ($2 = '' OR p.severity = $2)
		  AND ($3 = '' OR p.title ILIKE $3 OR p.kb ILIKE $3 OR p.update_id ILIKE $3)`+sc+`
		GROUP BY p.update_id
		ORDER BY CASE max(p.severity) WHEN 'Critical' THEN 0 WHEN 'Important' THEN 1 WHEN 'Moderate' THEN 2
			WHEN 'Low' THEN 3 ELSE 4 END, count(DISTINCT p.machine_id) DESC, max(p.title)
		LIMIT $4`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []FleetPatch{}
	for rows.Next() {
		var p FleetPatch
		if err := rows.Scan(&p.UpdateID, &p.KB, &p.Title, &p.Classification, &p.Severity, &p.Platform, &p.ReleasedAt,
			&p.RebootRequired, &p.CVECount, &p.Machines); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PatchMachine, güncellemenin eksik olduğu makinedir.
type PatchMachine struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Platform string `json:"os_platform"`
	OSName   string `json:"os_name"`
}

// PatchMachines, güncellemenin eksik olduğu aktif makineleri döner (kapsama göre).
func (s *Store) PatchMachines(ctx context.Context, updateID string, scope []string) ([]PatchMachine, error) {
	args := []any{updateID}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	sc := ""
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		sc = " AND " + c
	}
	rows, err := s.pool.Query(ctx, `
		SELECT m.id, m.hostname, m.os_platform, m.os_name
		FROM missing_patches p JOIN machines m ON m.id = p.machine_id
		WHERE p.update_id = $1 AND m.status = 'active'`+sc+`
		ORDER BY lower(m.hostname)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PatchMachine{}
	for rows.Next() {
		var m PatchMachine
		if err := rows.Scan(&m.ID, &m.Hostname, &m.Platform, &m.OSName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// VulnerableApp, açığı bulunan bir uygulama sürümüdür (gösterge paneli).
type VulnerableApp struct {
	App      string  `json:"app"` // "ad sürüm"
	Machines int     `json:"machines"`
	CVEs     int     `json:"cves"`
	MaxRisk  float32 `json:"max_risk"`
}

// DashboardOps, gösterge panelinin işletim özetidir: en çok makinede eksik olan
// güncellemeler ve açığı olan (güncel olmayan) uygulama sürümleri.
type DashboardOps struct {
	TopPatches     []FleetPatch    `json:"top_patches"`
	VulnerableApps []VulnerableApp `json:"vulnerable_apps"`
}

// GetDashboardOps, işletim özetini kullanıcı kapsamına göre üretir.
func (s *Store) GetDashboardOps(ctx context.Context, scope []string, limit int) (*DashboardOps, error) {
	out := &DashboardOps{TopPatches: []FleetPatch{}, VulnerableApps: []VulnerableApp{}}
	args := []any{limit}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	sc := ""
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		sc = " AND " + c
	}
	rows, err := s.pool.Query(ctx, `
		SELECT p.update_id, max(p.kb), max(p.title), max(p.classification), max(p.severity), max(m.os_platform),
		       max(p.released_at), bool_or(p.reboot_required), max(cardinality(p.cves)), count(DISTINCT p.machine_id)
		FROM missing_patches p JOIN machines m ON m.id = p.machine_id
		WHERE m.status = 'active'`+sc+`
		GROUP BY p.update_id
		ORDER BY count(DISTINCT p.machine_id) DESC, max(p.title)
		LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p FleetPatch
		if err := rows.Scan(&p.UpdateID, &p.KB, &p.Title, &p.Classification, &p.Severity, &p.Platform, &p.ReleasedAt,
			&p.RebootRequired, &p.CVECount, &p.Machines); err != nil {
			rows.Close()
			return nil, err
		}
		out.TopPatches = append(out.TopPatches, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Uygulama kaynaklı bulgularda refs, "ad sürüm" bilgisini taşır.
	rows, err = s.pool.Query(ctx, `
		SELECT ref, count(DISTINCT v.machine_id), count(DISTINCT v.cve_id), max(v.risk_score)
		FROM machine_vulnerabilities v JOIN machines m ON m.id = v.machine_id, unnest(v.refs) ref
		WHERE 'app' = ANY(v.sources) AND m.status = 'active'`+sc+`
		GROUP BY ref
		ORDER BY count(DISTINCT v.machine_id) DESC, max(v.risk_score) DESC
		LIMIT $1`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var a VulnerableApp
		if err := rows.Scan(&a.App, &a.Machines, &a.CVEs, &a.MaxRisk); err != nil {
			return nil, err
		}
		out.VulnerableApps = append(out.VulnerableApps, a)
	}
	return out, rows.Err()
}
