package store

import (
	"context"
	"time"
)

// User, konsol kullanıcısıdır.
type User struct {
	ID           string
	Username     string
	DisplayName  string
	Source       string
	PasswordHash string
	Role         string
	IsRecovery   bool
	Disabled     bool
	CreatedAt    time.Time
	LastLoginAt  *time.Time
}

const userColumns = `id, username, display_name, source, coalesce(password_hash, ''), role,
	is_recovery, disabled, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Source, &u.PasswordHash, &u.Role,
		&u.IsRecovery, &u.Disabled, &u.CreatedAt, &u.LastLoginAt)
	if err != nil {
		return nil, notFound(err)
	}
	return &u, nil
}

// CreateLocalUser, parola özetiyle yerel kullanıcı oluşturur.
func (s *Store) CreateLocalUser(ctx context.Context, username, displayName, passwordHash, role string, recovery bool) (*User, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO users (username, display_name, source, password_hash, role, is_recovery)
		VALUES ($1, $2, 'local', $3, $4, $5)
		RETURNING `+userColumns, username, displayName, passwordHash, role, recovery)
	u, err := scanUser(row)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return u, err
}

// GetUserByUsername, kullanıcı adını büyük/küçük harf duyarsız arar.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE lower(username) = lower($1)`, username))
}

// CountUsers, toplam kullanıcı sayısıdır (ilk kurulum kontrolü için).
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

// TouchLastLogin, başarılı girişin zamanını kaydeder.
func (s *Store) TouchLastLogin(ctx context.Context, userID string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET last_login_at = $2 WHERE id = $1`, userID, at)
	return err
}
