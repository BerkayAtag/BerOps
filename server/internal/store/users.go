package store

import (
	"context"
	"errors"
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
	// ScopeOUs, kullanıcının erişebildiği OU'lardır; boşsa tüm makineler. Admin rolünde yok sayılır.
	ScopeOUs []string
	ADDN     string
	Email    string
}

// Scope, kullanıcının etkin makine kapsamıdır (nil: kısıtsız).
func (u User) Scope() []string {
	if u.Role == "admin" || len(u.ScopeOUs) == 0 {
		return nil
	}
	return u.ScopeOUs
}

const userColumns = `id, username, display_name, source, coalesce(password_hash, ''), role,
	is_recovery, disabled, created_at, last_login_at, scope_ous, ad_dn, email`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Source, &u.PasswordHash, &u.Role,
		&u.IsRecovery, &u.Disabled, &u.CreatedAt, &u.LastLoginAt, &u.ScopeOUs, &u.ADDN, &u.Email)
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

// GetUser, kullanıcıyı kimlikle döner.
func (s *Store) GetUser(ctx context.Context, id string) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// ListUsers, tüm kullanıcıları ada göre döner.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY lower(username)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UserUpdate, kullanıcıda değiştirilecek alanlardır (nil: değişmez).
type UserUpdate struct {
	DisplayName  *string
	Role         *string
	Disabled     *bool
	ScopeOUs     *[]string
	PasswordHash *string
}

// UpdateUser, alanları günceller.
func (s *Store) UpdateUser(ctx context.Context, id string, u UserUpdate) (*User, error) {
	return scanUser(s.pool.QueryRow(ctx, `
		UPDATE users SET
			display_name = coalesce($2, display_name),
			role = coalesce($3, role),
			disabled = coalesce($4, disabled),
			scope_ous = coalesce($5, scope_ous),
			password_hash = coalesce($6, password_hash)
		WHERE id = $1 RETURNING `+userColumns, id, u.DisplayName, u.Role, u.Disabled, u.ScopeOUs, u.PasswordHash))
}

// CountActiveAdmins, devre dışı olmayan admin sayısıdır (exceptID hariç).
func (s *Store) CountActiveAdmins(ctx context.Context, exceptID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled AND id::text <> $1`, exceptID).Scan(&n)
	return n, err
}

// ADUser, AD girişinde oluşturulan/güncellenen kullanıcı bilgisidir.
type ADUser struct {
	Username    string
	DisplayName string
	Email       string
	DN          string
	Role        string
	ScopeOUs    []string
}

// UpsertADUser, AD kullanıcısını oluşturur veya rolünü, kapsamını ve bilgilerini günceller.
// Aynı adda yerel bir hesap varsa ErrConflict döner (yerel hesap AD girişiyle ele geçirilemez).
func (s *Store) UpsertADUser(ctx context.Context, a ADUser, at time.Time) (*User, error) {
	existing, err := s.GetUserByUsername(ctx, a.Username)
	switch {
	case err == nil && existing.Source != "ad":
		return nil, ErrConflict
	case err == nil:
		return scanUser(s.pool.QueryRow(ctx, `
			UPDATE users SET display_name = $2, email = $3, ad_dn = $4, role = $5, scope_ous = $6, last_login_at = $7
			WHERE id = $1 RETURNING `+userColumns,
			existing.ID, a.DisplayName, a.Email, a.DN, a.Role, nonNilStrings(a.ScopeOUs), at))
	case !errors.Is(err, ErrNotFound):
		return nil, err
	}
	u, err := scanUser(s.pool.QueryRow(ctx, `
		INSERT INTO users (username, display_name, source, role, email, ad_dn, scope_ous, last_login_at)
		VALUES ($1, $2, 'ad', $3, $4, $5, $6, $7) RETURNING `+userColumns,
		a.Username, a.DisplayName, a.Role, a.Email, a.DN, nonNilStrings(a.ScopeOUs), at))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return u, err
}
