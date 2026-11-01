package store

import (
	"context"
	"time"
)

// APIKey, dış sistemler için REST API anahtarıdır. Anahtarın kendisi saklanmaz; yalnızca özeti.
type APIKey struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Role       string     `json:"role"`
	ScopeOUs   []string   `json:"scope_ous"`
	CreatedBy  *string    `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

const apiKeyColumns = `id, name, key_prefix, role, scope_ous, created_by, created_at, expires_at, last_used_at, revoked_at`

func scanAPIKey(row interface{ Scan(...any) error }) (*APIKey, error) {
	var k APIKey
	if err := row.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.Role, &k.ScopeOUs, &k.CreatedBy, &k.CreatedAt, &k.ExpiresAt,
		&k.LastUsedAt, &k.RevokedAt); err != nil {
		return nil, notFound(err)
	}
	return &k, nil
}

// CreateAPIKey, anahtar kaydını ekler.
func (s *Store) CreateAPIKey(ctx context.Context, name, prefix string, hash []byte, role string, scope []string,
	createdBy string, expires *time.Time) (*APIKey, error) {
	return scanAPIKey(s.pool.QueryRow(ctx, `
		INSERT INTO api_keys (name, key_prefix, key_hash, role, scope_ous, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+apiKeyColumns,
		name, prefix, hash, role, nonNilStrings(scope), nullableUUID(createdBy), expires))
}

// ListAPIKeys, anahtarları yeniden eskiye döner.
func (s *Store) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+apiKeyColumns+` FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// ActiveAPIKey, özete karşılık gelen, iptal edilmemiş ve süresi dolmamış anahtarı döner ve son
// kullanım zamanını (en çok dakikada bir) günceller.
func (s *Store) ActiveAPIKey(ctx context.Context, hash []byte, now time.Time) (*APIKey, error) {
	k, err := scanAPIKey(s.pool.QueryRow(ctx, `
		SELECT `+apiKeyColumns+` FROM api_keys
		WHERE key_hash = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)`, hash, now))
	if err != nil {
		return nil, err
	}
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		_, _ = s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = $2 WHERE id = $1`, k.ID, now)
	}
	return k, nil
}

// RevokeAPIKey, anahtarı iptal eder.
func (s *Store) RevokeAPIKey(ctx context.Context, id string, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE api_keys SET revoked_at = $2 WHERE id = $1 AND revoked_at IS NULL`, id, now)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}
