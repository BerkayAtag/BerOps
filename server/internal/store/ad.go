package store

import (
	"context"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/ad"
)

// ADSettings, AD bağlantı ayarlarıdır. Parola şifreli saklanır ve API'den dönmez.
type ADSettings struct {
	Enabled         bool      `json:"enabled"`
	URL             string    `json:"url"`
	BaseDN          string    `json:"base_dn"`
	BindDN          string    `json:"bind_dn"`
	BindPasswordEnc []byte    `json:"-"`
	HasPassword     bool      `json:"has_password"`
	UserAttr        string    `json:"user_attr"`
	UserFilter      string    `json:"user_filter"`
	CACertPEM       string    `json:"ca_cert_pem"`
	TimeoutSeconds  int       `json:"timeout_seconds"`
	ComputersBaseDN string    `json:"computers_base_dn"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// GetADSettings, ayarları döner; kayıt yoksa kapalı varsayılanları döner.
func (s *Store) GetADSettings(ctx context.Context) (*ADSettings, error) {
	a := &ADSettings{UserAttr: "sAMAccountName", UserFilter: "(&(objectCategory=person)(objectClass=user))", TimeoutSeconds: 10}
	err := s.pool.QueryRow(ctx, `SELECT enabled, url, base_dn, bind_dn, bind_password_enc, user_attr, user_filter,
		ca_cert_pem, timeout_seconds, computers_base_dn, updated_at FROM ad_settings WHERE id = 1`).
		Scan(&a.Enabled, &a.URL, &a.BaseDN, &a.BindDN, &a.BindPasswordEnc, &a.UserAttr, &a.UserFilter, &a.CACertPEM,
			&a.TimeoutSeconds, &a.ComputersBaseDN, &a.UpdatedAt)
	if err := notFound(err); err != nil && err != ErrNotFound {
		return nil, err
	}
	a.HasPassword = len(a.BindPasswordEnc) > 0
	return a, nil
}

// SaveADSettings, ayarları kaydeder. passwordEnc nil ise mevcut parola korunur.
func (s *Store) SaveADSettings(ctx context.Context, a ADSettings, passwordEnc []byte, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO ad_settings (id, enabled, url, base_dn, bind_dn, bind_password_enc, user_attr, user_filter, ca_cert_pem,
			timeout_seconds, computers_base_dn, updated_by)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, url = EXCLUDED.url, base_dn = EXCLUDED.base_dn,
			bind_dn = EXCLUDED.bind_dn, bind_password_enc = coalesce(EXCLUDED.bind_password_enc, ad_settings.bind_password_enc),
			user_attr = EXCLUDED.user_attr, user_filter = EXCLUDED.user_filter, ca_cert_pem = EXCLUDED.ca_cert_pem,
			timeout_seconds = EXCLUDED.timeout_seconds, computers_base_dn = EXCLUDED.computers_base_dn,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		a.Enabled, a.URL, a.BaseDN, a.BindDN, passwordEnc, a.UserAttr, a.UserFilter, a.CACertPEM, a.TimeoutSeconds,
		a.ComputersBaseDN, nullableUUID(userID))
	return err
}

// ListADMappings, grup → rol eşlemelerini döner.
func (s *Store) ListADMappings(ctx context.Context) ([]ad.Mapping, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, group_dn, role, scope_ous FROM ad_group_roles ORDER BY role, lower(group_dn)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ad.Mapping{}
	for rows.Next() {
		var m ad.Mapping
		if err := rows.Scan(&m.ID, &m.GroupDN, &m.Role, &m.ScopeOUs); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// CreateADMapping, eşleme ekler; aynı grup varsa ErrConflict döner.
func (s *Store) CreateADMapping(ctx context.Context, m ad.Mapping, userID string) (*ad.Mapping, error) {
	err := s.pool.QueryRow(ctx, `INSERT INTO ad_group_roles (group_dn, role, scope_ous, created_by) VALUES ($1, $2, $3, $4) RETURNING id`,
		m.GroupDN, m.Role, nonNilStrings(m.ScopeOUs), nullableUUID(userID)).Scan(&m.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return &m, err
}

// DeleteADMapping, eşlemeyi siler.
func (s *Store) DeleteADMapping(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM ad_group_roles WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MachineHostnames, kayıtlı makinelerin küçük harfli adlarını döner (AD bilgisayar karşılaştırması için).
func (s *Store) MachineHostnames(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, lower(hostname) FROM machines WHERE status IN ('active', 'pending')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, h string
		if err := rows.Scan(&id, &h); err != nil {
			return nil, err
		}
		out[h] = id
	}
	return out, rows.Err()
}
