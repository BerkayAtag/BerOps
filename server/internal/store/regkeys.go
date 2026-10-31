package store

import (
	"context"
	"time"
)

// RegistrationKey, ajan kayıt anahtarının meta verisidir (anahtarın kendisi saklanmaz).
type RegistrationKey struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	KeyPrefix       string     `json:"key_prefix"`
	RequireApproval bool       `json:"require_approval"`
	MaxUses         *int       `json:"max_uses"`
	UseCount        int        `json:"use_count"`
	ExpiresAt       *time.Time `json:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

// NewRegistrationKey, kayıt anahtarı oluşturma parametreleridir.
type NewRegistrationKey struct {
	Name            string
	KeyHash         []byte
	KeyPrefix       string
	RequireApproval bool
	MaxUses         *int
	ExpiresAt       *time.Time
	CreatedBy       string // boş olabilir (CLI ile oluşturma)
}

const regKeyColumns = `id, name, key_prefix, require_approval, max_uses, use_count, expires_at, revoked_at, created_at`

func scanRegKey(row interface{ Scan(...any) error }) (*RegistrationKey, error) {
	var k RegistrationKey
	if err := row.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.RequireApproval, &k.MaxUses, &k.UseCount,
		&k.ExpiresAt, &k.RevokedAt, &k.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &k, nil
}

// CreateRegistrationKey, yeni kayıt anahtarı ekler.
func (s *Store) CreateRegistrationKey(ctx context.Context, n NewRegistrationKey) (*RegistrationKey, error) {
	var createdBy any
	if n.CreatedBy != "" {
		createdBy = n.CreatedBy
	}
	return scanRegKey(s.pool.QueryRow(ctx, `
		INSERT INTO registration_keys (name, key_hash, key_prefix, require_approval, max_uses, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING `+regKeyColumns,
		n.Name, n.KeyHash, n.KeyPrefix, n.RequireApproval, n.MaxUses, n.ExpiresAt, createdBy))
}

// ConsumeRegistrationKey, geçerli bir anahtarın kullanım sayacını atomik olarak artırır.
// Anahtar yoksa, iptal edilmişse, süresi dolmuşsa veya kullanım hakkı bittiyse ErrNotFound döner;
// çağıran bu durumları ayırt etmez, böylece saldırgan anahtarın varlığını öğrenemez.
func (s *Store) ConsumeRegistrationKey(ctx context.Context, keyHash []byte, now time.Time) (*RegistrationKey, error) {
	return scanRegKey(s.pool.QueryRow(ctx, `
		UPDATE registration_keys SET use_count = use_count + 1
		WHERE key_hash = $1
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > $2)
		  AND (max_uses IS NULL OR use_count < max_uses)
		RETURNING `+regKeyColumns, keyHash, now))
}

// ListRegistrationKeys, tüm anahtarları en yeniden eskiye döner.
func (s *Store) ListRegistrationKeys(ctx context.Context) ([]RegistrationKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+regKeyColumns+` FROM registration_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RegistrationKey{}
	for rows.Next() {
		k, err := scanRegKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// RevokeRegistrationKey, anahtarı iptal eder. Zaten iptal edilmişse ErrNotFound döner.
func (s *Store) RevokeRegistrationKey(ctx context.Context, id string, at time.Time) (*RegistrationKey, error) {
	return scanRegKey(s.pool.QueryRow(ctx, `
		UPDATE registration_keys SET revoked_at = $2
		WHERE id = $1 AND revoked_at IS NULL
		RETURNING `+regKeyColumns, id, at))
}
