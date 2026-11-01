package store

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// Package, paket kütüphanesindeki bir kayıttır.
type Package struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	Publisher      string    `json:"publisher"`
	Platform       string    `json:"platform"`
	Description    string    `json:"description"`
	Installer      string    `json:"installer"`
	InstallCommand string    `json:"install_command"`
	Shell          string    `json:"shell"`
	SuccessCodes   []int32   `json:"success_codes"`
	DetectName     string    `json:"detect_name"`
	FileName       string    `json:"file_name"`
	FileSize       int64     `json:"file_size"`
	FileSHA256     string    `json:"file_sha256"`
	CreatedBy      *string   `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
}

const packageColumns = `id, name, version, publisher, platform, description, installer, install_command, shell,
	success_codes, detect_name, file_name, file_size, file_sha256, created_by, created_at`

func scanPackage(row interface{ Scan(...any) error }) (*Package, error) {
	var p Package
	if err := row.Scan(&p.ID, &p.Name, &p.Version, &p.Publisher, &p.Platform, &p.Description, &p.Installer,
		&p.InstallCommand, &p.Shell, &p.SuccessCodes, &p.DetectName, &p.FileName, &p.FileSize, &p.FileSHA256,
		&p.CreatedBy, &p.CreatedAt); err != nil {
		return nil, notFound(err)
	}
	return &p, nil
}

// CreatePackage, paketi kaydeder. Aynı platformda aynı ad ve sürüm varsa ErrConflict döner.
func (s *Store) CreatePackage(ctx context.Context, p Package) (*Package, error) {
	out, err := scanPackage(s.pool.QueryRow(ctx, `
		INSERT INTO packages (name, version, publisher, platform, description, installer, install_command, shell,
			success_codes, detect_name, file_name, file_size, file_sha256, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
		RETURNING `+packageColumns,
		p.Name, p.Version, p.Publisher, p.Platform, p.Description, p.Installer, p.InstallCommand, p.Shell,
		p.SuccessCodes, p.DetectName, p.FileName, p.FileSize, p.FileSHA256, p.CreatedBy))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return out, err
}

// GetPackage, silinmemiş paketi döner.
func (s *Store) GetPackage(ctx context.Context, id string) (*Package, error) {
	return scanPackage(s.pool.QueryRow(ctx, `SELECT `+packageColumns+` FROM packages WHERE id = $1 AND deleted_at IS NULL`, id))
}

// ListPackages, silinmemiş paketleri ad ve sürüme göre döner.
func (s *Store) ListPackages(ctx context.Context, platform, search string) ([]Package, error) {
	pattern := ""
	if q := strings.TrimSpace(search); q != "" {
		pattern = "%" + escapeLike(q) + "%"
	}
	rows, err := s.pool.Query(ctx, `SELECT `+packageColumns+` FROM packages
		WHERE deleted_at IS NULL AND ($1 = '' OR platform = $1)
		  AND ($2 = '' OR name ILIKE $2 OR publisher ILIKE $2 OR file_name ILIKE $2)
		ORDER BY lower(name), created_at DESC`, platform, pattern)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		p, err := scanPackage(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// DeletePackage, paketi kütüphaneden kaldırır (geçmiş aksiyonlar için kayıt saklanır) ve
// dosyanın başka bir paket veya açık aksiyon tarafından kullanılıp kullanılmadığını döner.
func (s *Store) DeletePackage(ctx context.Context, id string, at time.Time) (sha string, fileInUse bool, err error) {
	err = s.pool.QueryRow(ctx, `UPDATE packages SET deleted_at = $2 WHERE id = $1 AND deleted_at IS NULL RETURNING file_sha256`,
		id, at).Scan(&sha)
	if err != nil {
		return "", false, notFound(err)
	}
	err = s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM packages WHERE file_sha256 = $1 AND deleted_at IS NULL)
		    OR EXISTS (SELECT 1 FROM actions a JOIN packages p ON p.id = a.package_id
		               WHERE p.file_sha256 = $1 AND a.status IN ('pending_approval', 'active'))`, sha).Scan(&fileInUse)
	return sha, fileInUse, err
}

// PackageFileReferenced, dosya özetinin silinmemiş bir paket veya açık aksiyon tarafından
// kullanılıp kullanılmadığını döner.
func (s *Store) PackageFileReferenced(ctx context.Context, sha string) (bool, error) {
	var used bool
	err := s.pool.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM packages WHERE file_sha256 = $1 AND deleted_at IS NULL)
		    OR EXISTS (SELECT 1 FROM actions a JOIN packages p ON p.id = a.package_id
		               WHERE p.file_sha256 = $1 AND a.status IN ('pending_approval', 'active'))`, sha).Scan(&used)
	return used, err
}

// AppInstall, bir makinedeki uygulama kurulumudur (güncelleme tespiti için).
type AppInstall struct {
	MachineID string `json:"machine_id"`
	Hostname  string `json:"hostname"`
	Online    bool   `json:"-"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// DistinctAppNames, platformdaki aktif makinelerde kurulu farklı uygulama adlarını döner.
func (s *Store) DistinctAppNames(ctx context.Context, platform string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT a.name FROM installed_apps a JOIN machines m ON m.id = a.machine_id
		WHERE m.status = 'active' AND m.os_platform = $1 AND a.source <> 'pkg'`, platform)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// AppInstalls, verilen adlardaki uygulamaların aktif makinelerdeki kurulumlarını döner.
func (s *Store) AppInstalls(ctx context.Context, platform string, names []string, scope []string) ([]AppInstall, error) {
	args := []any{platform, names}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	sc := ""
	if c := scopeCond("m.ad_ou", scope, arg); c != "" {
		sc = " AND " + c
	}
	rows, err := s.pool.Query(ctx, `
		SELECT m.id, m.hostname, a.name, a.version FROM installed_apps a JOIN machines m ON m.id = a.machine_id
		WHERE m.status = 'active' AND m.os_platform = $1 AND a.name = ANY($2) AND a.source <> 'pkg'`+sc+`
		ORDER BY lower(m.hostname)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppInstall
	for rows.Next() {
		var a AppInstall
		if err := rows.Scan(&a.MachineID, &a.Hostname, &a.Name, &a.Version); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// TransferSettings, aktarım ve aksiyon ayarlarıdır.
type TransferSettings struct {
	PerClientKbps      int  `json:"per_client_kbps"`
	MaxUploadMB        int  `json:"max_upload_mb"`
	CommandApproval    bool `json:"command_approval"`
	DefaultExpiryHours int  `json:"default_expiry_hours"`
	// TotalKbps, tüm indirmelerin paylaştığı toplam sunucu çıkış sınırıdır (0 = sınırsız).
	TotalKbps int `json:"total_kbps"`
	// Profiles, saat bazlı istemci sınırlarıdır; eşleşen ilk profil PerClientKbps yerine geçer.
	Profiles []RateProfile `json:"profiles"`
}

// RateProfile, belirli gün ve saatlerde geçerli istemci başına hız sınırıdır (sunucu saatiyle).
// EndMinute < StartMinute ise aralık gece yarısını aşar (ör. 22:00-06:00).
type RateProfile struct {
	Name        string  `json:"name"`
	Weekdays    []int16 `json:"weekdays"` // 0 = Pazar
	StartMinute int     `json:"start_minute"`
	EndMinute   int     `json:"end_minute"`
	Kbps        int     `json:"kbps"`
}

// Matches, zamanın profile girip girmediğini döner. Gece yarısını aşan aralıkta sabah kısmı
// bir önceki günün profilidir.
func (p RateProfile) Matches(t time.Time) bool {
	minute := t.Hour()*60 + t.Minute()
	day := int16(t.Weekday())
	has := func(d int16) bool {
		for _, w := range p.Weekdays {
			if w == d {
				return true
			}
		}
		return false
	}
	if p.StartMinute <= p.EndMinute {
		return has(day) && minute >= p.StartMinute && minute < p.EndMinute
	}
	prev := (day + 6) % 7
	return (has(day) && minute >= p.StartMinute) || (has(prev) && minute < p.EndMinute)
}

// ClientKbps, verilen zamanda geçerli istemci başına sınırdır.
func (t TransferSettings) ClientKbps(now time.Time) int {
	for _, p := range t.Profiles {
		if p.Matches(now) {
			return p.Kbps
		}
	}
	return t.PerClientKbps
}

// DefaultTransferSettings, kurulumdaki varsayılanlardır: istemci başına 10 Mbps.
func DefaultTransferSettings() TransferSettings {
	return TransferSettings{PerClientKbps: 10_000, MaxUploadMB: 4096, CommandApproval: false, DefaultExpiryHours: 72,
		Profiles: []RateProfile{}}
}

// GetTransferSettings, ayarları döner; kayıt yoksa varsayılanları döner.
func (s *Store) GetTransferSettings(ctx context.Context) (TransferSettings, error) {
	t := DefaultTransferSettings()
	err := s.pool.QueryRow(ctx, `SELECT per_client_kbps, max_upload_mb, command_approval, default_expiry_hours, total_kbps, profiles
		FROM transfer_settings WHERE id = 1`).Scan(&t.PerClientKbps, &t.MaxUploadMB, &t.CommandApproval, &t.DefaultExpiryHours,
		&t.TotalKbps, &t.Profiles)
	if err := notFound(err); err != nil && err != ErrNotFound {
		return t, err
	}
	return t, nil
}

// SaveTransferSettings, ayarları kaydeder.
func (s *Store) SaveTransferSettings(ctx context.Context, t TransferSettings, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO transfer_settings (id, per_client_kbps, max_upload_mb, command_approval, default_expiry_hours, updated_by,
			total_kbps, profiles)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET per_client_kbps = EXCLUDED.per_client_kbps, max_upload_mb = EXCLUDED.max_upload_mb,
			command_approval = EXCLUDED.command_approval, default_expiry_hours = EXCLUDED.default_expiry_hours,
			total_kbps = EXCLUDED.total_kbps, profiles = EXCLUDED.profiles,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		t.PerClientKbps, t.MaxUploadMB, t.CommandApproval, t.DefaultExpiryHours, nullableUUID(userID), t.TotalKbps,
		nonNilProfiles(t.Profiles))
	return err
}

func nonNilProfiles(p []RateProfile) []RateProfile {
	if p == nil {
		return []RateProfile{}
	}
	return p
}
