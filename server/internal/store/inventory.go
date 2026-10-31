package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// InventorySummary, makinenin envanter özetidir.
type InventorySummary struct {
	OS                   *protocol.OSInventory `json:"os"`
	Hashes               map[string]string     `json:"-"`
	CollectedAt          time.Time             `json:"collected_at"`
	ReceivedAt           time.Time             `json:"received_at"`
	LastFullAt           *time.Time            `json:"last_full_at"`
	ScanDurationMs       int64                 `json:"scan_duration_ms"`
	MissingScanSource    string                `json:"missing_scan_source"`
	MissingScannedAt     *time.Time            `json:"missing_scanned_at"`
	ScanErrors           []string              `json:"scan_errors"`
	MissingCount         int                   `json:"missing_count"`
	MissingCriticalCount int                   `json:"missing_critical_count"`
	MissingSecurityCount int                   `json:"missing_security_count"`
	InstalledPatchCount  int                   `json:"installed_patch_count"`
	AppCount             int                   `json:"app_count"`
	RebootPending        bool                  `json:"reboot_pending"`
}

// InventoryState, heartbeat sırasında gereken asgari envanter durumudur.
type InventoryState struct {
	HasInventory    bool
	Hashes          map[string]string
	ReceivedAt      *time.Time
	ScanRequestedAt *time.Time
}

// GetInventoryState, heartbeat'te tam envanter veya yeniden tarama istenip istenmeyeceğine
// karar vermek için gereken bilgiyi döner.
func (s *Store) GetInventoryState(ctx context.Context, machineID string) (*InventoryState, error) {
	var st InventoryState
	var hashes []byte
	err := s.pool.QueryRow(ctx, `
		SELECT i.hashes, i.received_at, m.scan_requested_at
		FROM machines m LEFT JOIN machine_inventory i ON i.machine_id = m.id
		WHERE m.id = $1`, machineID).Scan(&hashes, &st.ReceivedAt, &st.ScanRequestedAt)
	if err != nil {
		return nil, notFound(err)
	}
	if hashes != nil {
		st.HasInventory = true
		if err := json.Unmarshal(hashes, &st.Hashes); err != nil {
			return nil, err
		}
	}
	return &st, nil
}

// ApplyInventory, raporda bulunan bölümleri tek transaction içinde yazar. Raporda olmayan
// bölümler değişmeden kalır (delta yükleme). Tam raporda bulunmayan bölümlerin özetleri
// silinir; böylece sonraki heartbeat'te tutarsızlık tespit edilir.
func (s *Store) ApplyInventory(ctx context.Context, machineID string, r *protocol.InventoryReport, receivedAt time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var existing []byte
		err := tx.QueryRow(ctx, `SELECT hashes FROM machine_inventory WHERE machine_id = $1 FOR UPDATE`, machineID).Scan(&existing)
		hashes := map[string]string{}
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		case !r.Full:
			if err := json.Unmarshal(existing, &hashes); err != nil {
				return err
			}
		}
		for _, sec := range r.Included {
			hashes[sec] = r.Hashes[sec]
		}
		hashJSON, err := json.Marshal(hashes)
		if err != nil {
			return err
		}

		var osJSON []byte
		if r.Has(protocol.SectionOS) {
			if osJSON, err = json.Marshal(r.OS); err != nil {
				return err
			}
		}
		var lastFull *time.Time
		if r.Full {
			lastFull = &r.CollectedAt
		}
		var scanSource string
		var scannedAt *time.Time
		if r.MissingScan != nil {
			scanSource, scannedAt = r.MissingScan.Source, &r.MissingScan.ScannedAt
		}
		errs := r.Errors
		if errs == nil {
			errs = []string{}
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO machine_inventory (machine_id, os, hashes, collected_at, received_at, last_full_at,
				scan_duration_ms, missing_scan_source, missing_scanned_at, scan_errors)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT (machine_id) DO UPDATE SET
				os = coalesce(EXCLUDED.os, machine_inventory.os),
				hashes = EXCLUDED.hashes,
				collected_at = EXCLUDED.collected_at,
				received_at = EXCLUDED.received_at,
				last_full_at = coalesce(EXCLUDED.last_full_at, machine_inventory.last_full_at),
				scan_duration_ms = EXCLUDED.scan_duration_ms,
				missing_scan_source = CASE WHEN EXCLUDED.missing_scan_source <> '' THEN EXCLUDED.missing_scan_source
					ELSE machine_inventory.missing_scan_source END,
				missing_scanned_at = coalesce(EXCLUDED.missing_scanned_at, machine_inventory.missing_scanned_at),
				scan_errors = EXCLUDED.scan_errors`,
			machineID, osJSON, hashJSON, r.CollectedAt, receivedAt, lastFull,
			r.ScanDurationMs, scanSource, scannedAt, errs); err != nil {
			return err
		}

		if r.Has(protocol.SectionOS) {
			if _, err := tx.Exec(ctx, `
				UPDATE machine_inventory SET reboot_pending = $2 WHERE machine_id = $1`, machineID, r.OS.RebootPending); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE machines SET ad_ou = $2 WHERE id = $1`, machineID, OUFromDN(r.OS.ADDN)); err != nil {
				return err
			}
		}
		if r.Has(protocol.SectionInstalledPatches) {
			if err := replaceInstalledPatches(ctx, tx, machineID, r.InstalledPatches); err != nil {
				return err
			}
		}
		if r.Has(protocol.SectionMissingPatches) {
			if err := replaceMissingPatches(ctx, tx, machineID, r.MissingPatches); err != nil {
				return err
			}
		}
		if r.Has(protocol.SectionApps) {
			if err := replaceApps(ctx, tx, machineID, r.Apps); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			UPDATE machine_inventory SET
				missing_count = (SELECT count(*) FROM missing_patches WHERE machine_id = $1),
				missing_critical_count = (SELECT count(*) FROM missing_patches WHERE machine_id = $1 AND severity = 'Critical'),
				missing_security_count = (SELECT count(*) FROM missing_patches WHERE machine_id = $1
					AND (classification IN ('Security Updates', 'Critical Updates') OR severity <> '' OR cardinality(cves) > 0)),
				installed_patch_count = (SELECT count(*) FROM installed_patches WHERE machine_id = $1),
				app_count = (SELECT count(*) FROM installed_apps WHERE machine_id = $1)
			WHERE machine_id = $1`, machineID); err != nil {
			return err
		}
		if r.Full {
			if _, err := tx.Exec(ctx, `UPDATE machines SET scan_requested_at = NULL
				WHERE id = $1 AND scan_requested_at <= $2`, machineID, receivedAt); err != nil {
				return err
			}
		}
		return nil
	})
}

// OUFromDN, bilgisayarın ayırt edici adından (CN=PC01,OU=İzmir,DC=corp,DC=example)
// bulunduğu OU yolunu (OU=İzmir,DC=corp,DC=example) çıkarır.
func OUFromDN(dn string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return ""
	}
	// CN değeri kaçışlı virgül (\,) içerebilir.
	for i := 0; i < len(dn); i++ {
		if dn[i] == '\\' {
			i++
			continue
		}
		if dn[i] == ',' {
			return strings.TrimSpace(dn[i+1:])
		}
	}
	return ""
}

func parseDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	return &t
}

func replaceInstalledPatches(ctx context.Context, tx pgx.Tx, machineID string, patches []protocol.InstalledPatch) error {
	if _, err := tx.Exec(ctx, `DELETE FROM installed_patches WHERE machine_id = $1`, machineID); err != nil {
		return err
	}
	seen := map[string]bool{}
	rows := make([][]any, 0, len(patches))
	for _, p := range patches {
		if p.ID == "" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		rows = append(rows, []any{machineID, p.ID, p.Title, parseDate(p.InstalledOn), p.Source})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"installed_patches"},
		[]string{"machine_id", "patch_id", "title", "installed_on", "source"}, pgx.CopyFromRows(rows))
	return err
}

func replaceMissingPatches(ctx context.Context, tx pgx.Tx, machineID string, patches []protocol.MissingPatch) error {
	if _, err := tx.Exec(ctx, `DELETE FROM missing_patches WHERE machine_id = $1`, machineID); err != nil {
		return err
	}
	seen := map[string]bool{}
	rows := make([][]any, 0, len(patches))
	for _, p := range patches {
		if p.ID == "" || seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		cves := p.CVEs
		if cves == nil {
			cves = []string{}
		}
		rows = append(rows, []any{machineID, p.ID, p.KB, p.Title, p.Classification, p.Severity, p.ReleasedAt,
			p.RebootRequired, p.SizeBytes, cves, p.Version, p.Recommended, p.SupportURL})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"missing_patches"},
		[]string{"machine_id", "update_id", "kb", "title", "classification", "severity", "released_at",
			"reboot_required", "size_bytes", "cves", "version", "recommended", "support_url"}, pgx.CopyFromRows(rows))
	return err
}

func replaceApps(ctx context.Context, tx pgx.Tx, machineID string, apps []protocol.App) error {
	if _, err := tx.Exec(ctx, `DELETE FROM installed_apps WHERE machine_id = $1`, machineID); err != nil {
		return err
	}
	rows := make([][]any, 0, len(apps))
	for _, a := range apps {
		if a.Name == "" {
			continue
		}
		rows = append(rows, []any{machineID, a.Name, a.Version, a.Publisher, parseDate(a.InstallDate),
			a.InstallLocation, a.Source, a.Identifier, a.Arch, a.Scope})
	}
	_, err := tx.CopyFrom(ctx, pgx.Identifier{"installed_apps"},
		[]string{"machine_id", "name", "version", "publisher", "install_date", "install_location", "source",
			"identifier", "arch", "scope"}, pgx.CopyFromRows(rows))
	return err
}

// GetInventorySummary, makinenin envanter özetini döner; envanter yoksa ErrNotFound.
func (s *Store) GetInventorySummary(ctx context.Context, machineID string) (*InventorySummary, error) {
	var sum InventorySummary
	var osJSON, hashes []byte
	err := s.pool.QueryRow(ctx, `
		SELECT os, hashes, collected_at, received_at, last_full_at, scan_duration_ms, missing_scan_source,
		       missing_scanned_at, scan_errors, missing_count, missing_critical_count, missing_security_count,
		       installed_patch_count, app_count, reboot_pending
		FROM machine_inventory WHERE machine_id = $1`, machineID).Scan(
		&osJSON, &hashes, &sum.CollectedAt, &sum.ReceivedAt, &sum.LastFullAt, &sum.ScanDurationMs,
		&sum.MissingScanSource, &sum.MissingScannedAt, &sum.ScanErrors, &sum.MissingCount,
		&sum.MissingCriticalCount, &sum.MissingSecurityCount, &sum.InstalledPatchCount, &sum.AppCount,
		&sum.RebootPending)
	if err != nil {
		return nil, notFound(err)
	}
	if osJSON != nil {
		sum.OS = &protocol.OSInventory{}
		if err := json.Unmarshal(osJSON, sum.OS); err != nil {
			return nil, err
		}
	}
	if err := json.Unmarshal(hashes, &sum.Hashes); err != nil {
		return nil, err
	}
	return &sum, nil
}

// ListMissingPatches, makinenin eksik yamalarını önem derecesine göre sıralı döner.
func (s *Store) ListMissingPatches(ctx context.Context, machineID string) ([]protocol.MissingPatch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT update_id, kb, title, classification, severity, released_at, reboot_required, size_bytes,
		       cves, version, recommended, support_url
		FROM missing_patches WHERE machine_id = $1
		ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'Important' THEN 1 WHEN 'Moderate' THEN 2
		                       WHEN 'Low' THEN 3 ELSE 4 END, released_at DESC NULLS LAST, title`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []protocol.MissingPatch{}
	for rows.Next() {
		var p protocol.MissingPatch
		if err := rows.Scan(&p.ID, &p.KB, &p.Title, &p.Classification, &p.Severity, &p.ReleasedAt,
			&p.RebootRequired, &p.SizeBytes, &p.CVEs, &p.Version, &p.Recommended, &p.SupportURL); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListInstalledPatches, makinenin kurulu yamalarını en yeniden eskiye döner.
func (s *Store) ListInstalledPatches(ctx context.Context, machineID string) ([]protocol.InstalledPatch, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT patch_id, title, coalesce(to_char(installed_on, 'YYYY-MM-DD'), ''), source
		FROM installed_patches WHERE machine_id = $1
		ORDER BY installed_on DESC NULLS LAST, patch_id`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []protocol.InstalledPatch{}
	for rows.Next() {
		var p protocol.InstalledPatch
		if err := rows.Scan(&p.ID, &p.Title, &p.InstalledOn, &p.Source); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListApps, makinedeki uygulamaları ada göre sıralı döner.
func (s *Store) ListApps(ctx context.Context, machineID string) ([]protocol.App, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT name, version, publisher, coalesce(to_char(install_date, 'YYYY-MM-DD'), ''), install_location,
		       source, identifier, arch, scope
		FROM installed_apps WHERE machine_id = $1 ORDER BY lower(name), version`, machineID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []protocol.App{}
	for rows.Next() {
		var a protocol.App
		if err := rows.Scan(&a.Name, &a.Version, &a.Publisher, &a.InstallDate, &a.InstallLocation, &a.Source,
			&a.Identifier, &a.Arch, &a.Scope); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RequestScan, makineler için yeniden tarama ister; etkilenen makine sayısını döner.
func (s *Store) RequestScan(ctx context.Context, machineIDs []string, at time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE machines SET scan_requested_at = $2
		WHERE id = ANY($1::uuid[]) AND status IN ('active', 'pending')`, machineIDs, at)
	return tag.RowsAffected(), err
}

// GetAgentSettings, kayıtlı ajan ayarlarını döner; hiç kaydedilmemişse varsayılanları.
func (s *Store) GetAgentSettings(ctx context.Context) (protocol.AgentSettings, error) {
	set := protocol.DefaultAgentSettings()
	var b []byte
	err := s.pool.QueryRow(ctx, `SELECT settings FROM agent_settings WHERE id = 1`).Scan(&b)
	if errors.Is(err, pgx.ErrNoRows) {
		return set, nil
	}
	if err != nil {
		return set, err
	}
	// Kayıtlı JSON'da olmayan (yeni eklenen) alanlar varsayılan değerlerini korur.
	if err := json.Unmarshal(b, &set); err != nil {
		return set, err
	}
	return set, nil
}

// SaveAgentSettings, ajan ayarlarını kaydeder.
func (s *Store) SaveAgentSettings(ctx context.Context, set protocol.AgentSettings, userID string) error {
	b, err := json.Marshal(set)
	if err != nil {
		return err
	}
	var by any
	if userID != "" {
		by = userID
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO agent_settings (id, settings, updated_at, updated_by) VALUES (1, $1, now(), $2)
		ON CONFLICT (id) DO UPDATE SET settings = EXCLUDED.settings, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		b, by)
	return err
}
