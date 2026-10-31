package store

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// Machine, kayıtlı bir ajanın sunucudaki kaydıdır.
type Machine struct {
	ID              string     `json:"id"`
	Hostname        string     `json:"hostname"`
	Status          string     `json:"status"`
	OSPlatform      string     `json:"os_platform"`
	OSName          string     `json:"os_name"`
	OSVersion       string     `json:"os_version"`
	OSBuild         string     `json:"os_build"`
	Arch            string     `json:"arch"`
	IPAddresses     []string   `json:"ip_addresses"`
	AgentVersion    string     `json:"agent_version"`
	ADOU            string     `json:"ad_ou"`
	CertSerial      string     `json:"-"`
	CertFingerprint string     `json:"cert_fingerprint"`
	CertExpiresAt   time.Time  `json:"cert_expires_at"`
	EnrolledAt      time.Time  `json:"enrolled_at"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	AgentStartedAt  *time.Time `json:"agent_started_at"`
	LastErrors      []string   `json:"last_errors"`
}

// NewMachine, kayıt sırasında oluşturulan makine kaydıdır.
type NewMachine struct {
	ID                string
	Status            string
	Host              protocol.HostInfo
	CertSerial        string
	CertFingerprint   string
	CertExpiresAt     time.Time
	RegistrationKeyID string
	EnrolledAt        time.Time
}

const machineColumns = `id, hostname, status, os_platform, os_name, os_version, os_build, arch,
	ip_addresses, agent_version, ad_ou, cert_serial, cert_fingerprint, cert_expires_at,
	enrolled_at, last_seen_at, agent_started_at, last_errors`

func scanMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	var m Machine
	if err := row.Scan(&m.ID, &m.Hostname, &m.Status, &m.OSPlatform, &m.OSName, &m.OSVersion, &m.OSBuild,
		&m.Arch, &m.IPAddresses, &m.AgentVersion, &m.ADOU, &m.CertSerial, &m.CertFingerprint, &m.CertExpiresAt,
		&m.EnrolledAt, &m.LastSeenAt, &m.AgentStartedAt, &m.LastErrors); err != nil {
		return nil, notFound(err)
	}
	return &m, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// CreateMachine, kayıt olan ajan için makine kaydı oluşturur.
func (s *Store) CreateMachine(ctx context.Context, n NewMachine) (*Machine, error) {
	h := n.Host
	return scanMachine(s.pool.QueryRow(ctx, `
		INSERT INTO machines (id, hostname, status, os_platform, os_name, os_version, os_build, arch,
			ip_addresses, agent_version, cert_serial, cert_fingerprint, cert_expires_at,
			registration_key_id, enrolled_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $15)
		RETURNING `+machineColumns,
		n.ID, h.Hostname, n.Status, h.OSPlatform, h.OSName, h.OSVersion, h.OSBuild, h.Arch,
		nonNil(h.IPAddresses), h.AgentVersion, n.CertSerial, n.CertFingerprint, n.CertExpiresAt,
		n.RegistrationKeyID, n.EnrolledAt))
}

// GetMachine, makineyi ID ile döner.
func (s *Store) GetMachine(ctx context.Context, id string) (*Machine, error) {
	return scanMachine(s.pool.QueryRow(ctx, `SELECT `+machineColumns+` FROM machines WHERE id = $1`, id))
}

// RecordHeartbeat, heartbeat ile gelen makine bilgisini ve son görülme zamanını günceller.
func (s *Store) RecordHeartbeat(ctx context.Context, id string, req protocol.HeartbeatRequest, at time.Time) (*Machine, error) {
	h := req.Host
	var started *time.Time
	if !req.AgentStartedAt.IsZero() {
		started = &req.AgentStartedAt
	}
	return scanMachine(s.pool.QueryRow(ctx, `
		UPDATE machines SET
			hostname = $2, os_name = $3, os_version = $4, os_build = $5, arch = $6,
			ip_addresses = $7, agent_version = $8, agent_started_at = $9, last_errors = $10,
			last_seen_at = $11
		WHERE id = $1
		RETURNING `+machineColumns,
		id, h.Hostname, h.OSName, h.OSVersion, h.OSBuild, h.Arch, nonNil(h.IPAddresses), h.AgentVersion,
		started, nonNil(req.Errors), at))
}

// SetMachineStatus, makine durumunu değiştirir (onay, reddetme, iptal).
func (s *Store) SetMachineStatus(ctx context.Context, id, status string) (*Machine, error) {
	return scanMachine(s.pool.QueryRow(ctx, `UPDATE machines SET status = $2 WHERE id = $1 RETURNING `+machineColumns, id, status))
}

// ListMachines, tüm makineleri hostname sırasıyla döner. Arama, filtre ve sayfalama Aşama 2'de eklenir.
func (s *Store) ListMachines(ctx context.Context) ([]Machine, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+machineColumns+` FROM machines ORDER BY lower(hostname), enrolled_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Machine{}
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// MachineListItem, makine listesi satırıdır (envanter sayaçlarıyla).
type MachineListItem struct {
	Machine
	Online               bool       `json:"online"`
	InventoryAt          *time.Time `json:"inventory_at"`
	MissingCount         int        `json:"missing_count"`
	MissingCriticalCount int        `json:"missing_critical_count"`
	MissingSecurityCount int        `json:"missing_security_count"`
	AppCount             int        `json:"app_count"`
	RebootPending        bool       `json:"reboot_pending"`
	VulnCount            int        `json:"vuln_count"`
	KEVCount             int        `json:"kev_count"`
	MaxRisk              float32    `json:"max_risk"`
}

// MachineFilter, makine listesi arama/filtre/sıralama/sayfalama parametreleridir.
type MachineFilter struct {
	Search   string // hostname, IP veya işletim sistemi içinde arar
	Platform string // windows, darwin
	Status   string // active, pending, rejected, revoked
	Online   *bool
	// OnlineWindow, makinenin çevrimiçi sayılması için son heartbeat'in en fazla yaşıdır.
	OnlineWindow time.Duration
	Sort         string // MachineSortColumns anahtarlarından biri
	Desc         bool
	Limit        int
	Offset       int
	Now          time.Time
	// Unlimited, rapor dışa aktarımında sayfa sınırını kaldırır.
	Unlimited bool
	// Scope, kullanıcının OU kapsamıdır (boş: tüm makineler).
	Scope []string
}

// MachineSortColumns, izin verilen sıralama alanlarıdır. Kullanıcı girdisi SQL'e
// yalnızca bu eşleme üzerinden girer.
var MachineSortColumns = map[string]string{
	"hostname":         "lower(m.hostname)",
	"os":               "m.os_name",
	"os_build":         "m.os_build",
	"agent_version":    "m.agent_version",
	"last_seen_at":     "m.last_seen_at",
	"enrolled_at":      "m.enrolled_at",
	"missing_count":    "coalesce(i.missing_count, -1)",
	"missing_critical": "coalesce(i.missing_critical_count, -1)",
	"app_count":        "coalesce(i.app_count, -1)",
	"risk":             "coalesce(r.max_risk, -1)",
	"vulns":            "coalesce(r.vuln_count, -1)",
	"status":           "m.status",
}

// ListMachinesFiltered, filtrelenmiş ve sayfalanmış makine listesi ile toplam kayıt sayısını döner.
func (s *Store) ListMachinesFiltered(ctx context.Context, f MachineFilter) ([]MachineListItem, int, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	// Çevrimiçi sınır parametresi yalnızca kullanıldığında eklenir; PostgreSQL kullanılmayan
	// parametrenin türünü belirleyemez.
	cutoff := ""
	onlineExpr := func() string {
		if cutoff == "" {
			cutoff = arg(f.Now.Add(-f.OnlineWindow))
		}
		return "(m.last_seen_at IS NOT NULL AND m.last_seen_at >= " + cutoff + " AND m.status IN ('active', 'pending'))"
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		p := arg("%" + escapeLike(q) + "%")
		where = append(where, "(m.hostname ILIKE "+p+" OR m.os_name ILIKE "+p+" OR m.os_build ILIKE "+p+
			" OR m.ad_ou ILIKE "+p+" OR array_to_string(m.ip_addresses, ' ') ILIKE "+p+")")
	}
	if f.Platform != "" {
		where = append(where, "m.os_platform = "+arg(f.Platform))
	}
	if f.Status != "" {
		where = append(where, "m.status = "+arg(f.Status))
	}
	if c := scopeCond("m.ad_ou", f.Scope, arg); c != "" {
		where = append(where, c)
	}
	if f.Online != nil {
		if *f.Online {
			where = append(where, onlineExpr())
		} else {
			where = append(where, "NOT "+onlineExpr())
		}
	}
	cond := ""
	if len(where) > 0 {
		cond = "WHERE " + strings.Join(where, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM machines m LEFT JOIN machine_inventory i ON i.machine_id = m.id `+cond,
		args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	col, ok := MachineSortColumns[f.Sort]
	if !ok {
		col = MachineSortColumns["hostname"]
	}
	dir := "ASC"
	if f.Desc {
		dir = "DESC"
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	if f.Unlimited {
		limit = maxExportRows
	}
	q := `SELECT ` + prefixed("m.", machineColumns) + `, ` + onlineExpr() + `,
		i.received_at, coalesce(i.missing_count, 0), coalesce(i.missing_critical_count, 0),
		coalesce(i.missing_security_count, 0), coalesce(i.app_count, 0), coalesce(i.reboot_pending, false),
		coalesce(r.vuln_count, 0), coalesce(r.kev_count, 0), coalesce(r.max_risk, 0)
		FROM machines m LEFT JOIN machine_inventory i ON i.machine_id = m.id
		LEFT JOIN machine_risk r ON r.machine_id = m.id ` + cond +
		` ORDER BY ` + col + ` ` + dir + ` NULLS LAST, lower(m.hostname), m.id LIMIT ` + arg(limit) + ` OFFSET ` + arg(max(f.Offset, 0))
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []MachineListItem{}
	for rows.Next() {
		var it MachineListItem
		m := &it.Machine
		if err := rows.Scan(&m.ID, &m.Hostname, &m.Status, &m.OSPlatform, &m.OSName, &m.OSVersion, &m.OSBuild,
			&m.Arch, &m.IPAddresses, &m.AgentVersion, &m.ADOU, &m.CertSerial, &m.CertFingerprint, &m.CertExpiresAt,
			&m.EnrolledAt, &m.LastSeenAt, &m.AgentStartedAt, &m.LastErrors,
			&it.Online, &it.InventoryAt, &it.MissingCount, &it.MissingCriticalCount, &it.MissingSecurityCount,
			&it.AppCount, &it.RebootPending, &it.VulnCount, &it.KEVCount, &it.MaxRisk); err != nil {
			return nil, 0, err
		}
		out = append(out, it)
	}
	return out, total, rows.Err()
}

// FleetSummary, gösterge paneli için filo sayaçlarıdır.
type FleetSummary struct {
	Total             int `json:"total"`
	Online            int `json:"online"`
	Pending           int `json:"pending"`
	WithInventory     int `json:"with_inventory"`
	FullyPatched      int `json:"fully_patched"`
	MissingTotal      int `json:"missing_total"`
	CriticalMachines  int `json:"critical_machines"`
	RebootPending     int `json:"reboot_pending"`
	Windows           int `json:"windows"`
	MacOS             int `json:"macos"`
	DistinctAppsCount int `json:"distinct_apps"`
}

// GetFleetSummary, aktif ve onay bekleyen makineler üzerinden filo sayaçlarını hesaplar.
func (s *Store) GetFleetSummary(ctx context.Context, now time.Time, onlineWindow time.Duration, scope []string) (*FleetSummary, error) {
	args := []any{now.Add(-onlineWindow)}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	cond := "m.status IN ('active', 'pending')"
	appsCond := ""
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		cond += " AND " + c
		appsCond = " WHERE a.machine_id IN (SELECT m.id FROM machines m WHERE " + c + ")"
	}
	var f FleetSummary
	err := s.pool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE m.last_seen_at >= $1),
		       count(*) FILTER (WHERE m.status = 'pending'),
		       count(i.machine_id),
		       count(*) FILTER (WHERE i.machine_id IS NOT NULL AND i.missing_count = 0 AND i.missing_scanned_at IS NOT NULL),
		       coalesce(sum(i.missing_count), 0),
		       count(*) FILTER (WHERE i.missing_critical_count > 0),
		       count(*) FILTER (WHERE i.reboot_pending),
		       count(*) FILTER (WHERE m.os_platform = 'windows'),
		       count(*) FILTER (WHERE m.os_platform = 'darwin'),
		       (SELECT count(DISTINCT lower(a.name)) FROM installed_apps a`+appsCond+`)
		FROM machines m LEFT JOIN machine_inventory i ON i.machine_id = m.id
		WHERE `+cond, args...).Scan(
		&f.Total, &f.Online, &f.Pending, &f.WithInventory, &f.FullyPatched, &f.MissingTotal,
		&f.CriticalMachines, &f.RebootPending, &f.Windows, &f.MacOS, &f.DistinctAppsCount)
	return &f, err
}

// scopeCond, OU kapsamı koşuludur: makinenin OU'su kapsamdaki bir OU'ya eşit veya onun altında
// olmalıdır. Kapsam boşsa "" döner. Büyük/küçük harf dönüşümü iki tarafta da PostgreSQL'de
// yapılır (Türkçe İ gibi harflerde Go ile farklılık olmasın).
func scopeCond(col string, scope []string, arg func(any) string) string {
	var pats []string
	for _, sc := range scope {
		if sc = strings.TrimSpace(sc); sc != "" {
			e := escapeLike(sc)
			pats = append(pats, e, "%,"+e)
		}
	}
	if len(scope) > 0 && len(pats) == 0 {
		return "false"
	}
	if len(pats) == 0 {
		return ""
	}
	return "lower(" + col + ") LIKE ANY (SELECT lower(x) FROM unnest(" + arg(pats) + "::text[]) x)"
}

func prefixed(prefix, cols string) string {
	parts := strings.Split(cols, ",")
	for i, p := range parts {
		parts[i] = prefix + strings.TrimSpace(p)
	}
	return strings.Join(parts, ", ")
}

// escapeLike, LIKE kalıbındaki özel karakterleri kaçışlar.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}
