package store

import (
	"context"
	"time"
)

// Session, kullanıcı bilgisiyle birlikte konsol oturumudur.
type Session struct {
	TokenHash  []byte
	CSRFToken  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	User       User
}

// CreateSession, yeni oturum kaydı ekler.
func (s *Store) CreateSession(ctx context.Context, tokenHash []byte, userID, csrf string, expiresAt time.Time, ip, userAgent string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at, ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6)`, tokenHash, userID, csrf, expiresAt, ip, userAgent)
	return err
}

// GetSession, oturumu kullanıcısıyla birlikte döner. Süre kontrolü çağırana aittir.
func (s *Store) GetSession(ctx context.Context, tokenHash []byte) (*Session, error) {
	var ss Session
	var u User
	err := s.pool.QueryRow(ctx, `
		SELECT s.token_hash, s.csrf_token, s.created_at, s.last_seen_at, s.expires_at,
		       u.id, u.username, u.display_name, u.source, u.role, u.is_recovery, u.disabled
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`, tokenHash).Scan(
		&ss.TokenHash, &ss.CSRFToken, &ss.CreatedAt, &ss.LastSeenAt, &ss.ExpiresAt,
		&u.ID, &u.Username, &u.DisplayName, &u.Source, &u.Role, &u.IsRecovery, &u.Disabled)
	if err != nil {
		return nil, notFound(err)
	}
	ss.User = u
	return &ss, nil
}

// TouchSession, oturumun son etkinlik zamanını günceller.
func (s *Store) TouchSession(ctx context.Context, tokenHash []byte, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1`, tokenHash, at)
	return err
}

// DeleteSession, oturumu siler (çıkış).
func (s *Store) DeleteSession(ctx context.Context, tokenHash []byte) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

// DeleteExpiredSessions, mutlak süresi dolmuş veya boşta kalma süresini aşmış oturumları siler.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time, idle time.Duration) (int64, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at <= $1 OR last_seen_at <= $2`, now, now.Add(-idle))
	return tag.RowsAffected(), err
}
