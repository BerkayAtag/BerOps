package store

import (
	"context"
	"time"
)

// Relay, şube relay kaydıdır.
type Relay struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Hostnames     []string   `json:"hostnames"`
	CertSerial    string     `json:"-"`
	CertExpiresAt time.Time  `json:"cert_expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	LastSeenAt    *time.Time `json:"last_seen_at"`
	LastIP        string     `json:"last_ip"`
	RevokedAt     *time.Time `json:"revoked_at"`
}

const relayColumns = `id, name, hostnames, cert_serial, cert_expires_at, created_at, last_seen_at, last_ip, revoked_at`

func scanRelay(row interface{ Scan(...any) error }) (*Relay, error) {
	var r Relay
	if err := row.Scan(&r.ID, &r.Name, &r.Hostnames, &r.CertSerial, &r.CertExpiresAt, &r.CreatedAt, &r.LastSeenAt,
		&r.LastIP, &r.RevokedAt); err != nil {
		return nil, notFound(err)
	}
	return &r, nil
}

// CreateRelay, relay kaydı ekler.
func (s *Store) CreateRelay(ctx context.Context, id, name string, hosts []string, serial string, expires time.Time) (*Relay, error) {
	return scanRelay(s.pool.QueryRow(ctx, `INSERT INTO relays (id, name, hostnames, cert_serial, cert_expires_at)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+relayColumns, id, name, hosts, serial, expires))
}

// GetRelay, relay'i kimlikle döner.
func (s *Store) GetRelay(ctx context.Context, id string) (*Relay, error) {
	return scanRelay(s.pool.QueryRow(ctx, `SELECT `+relayColumns+` FROM relays WHERE id = $1`, id))
}

// ListRelays, relay'leri ada göre döner.
func (s *Store) ListRelays(ctx context.Context) ([]Relay, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+relayColumns+` FROM relays ORDER BY revoked_at IS NOT NULL, lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Relay{}
	for rows.Next() {
		r, err := scanRelay(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// TouchRelay, relay'in son görülme zamanını en fazla dakikada bir günceller.
func (s *Store) TouchRelay(ctx context.Context, id, ip string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE relays SET last_seen_at = $2, last_ip = $3
		WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < $2::timestamptz - interval '1 minute')`, id, at, ip)
	return err
}

// RevokeRelay, relay'i iptal eder; sertifikası artık kabul edilmez.
func (s *Store) RevokeRelay(ctx context.Context, id string, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE relays SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// PackageFileKnown, özetin kütüphanedeki (silinmemiş) bir pakete veya açık bir aksiyona ait
// olup olmadığını döner (relay'in yalnızca dağıtılan dosyaları çekebilmesi için).
func (s *Store) PackageFileKnown(ctx context.Context, sha string) (bool, error) {
	return s.PackageFileReferenced(ctx, sha)
}
