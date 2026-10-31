package store

import (
	"context"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
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
