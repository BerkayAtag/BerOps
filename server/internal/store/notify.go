package store

import (
	"context"
	"encoding/json"
	"time"
)

// Bildirim olayları.
const (
	EventActionCompleted = "action.completed"
	EventKEVNew          = "vulnerability.kev_new"
	EventCVESyncFailed   = "cve.sync_failed"
)

// AllEvents, abone olunabilecek olaylardır.
var AllEvents = []string{EventActionCompleted, EventKEVNew, EventCVESyncFailed}

// Channel, bildirim kanalıdır. Gizli değer (SMTP parolası, webhook imza anahtarı) şifreli tutulur.
type Channel struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Kind       string          `json:"kind"`
	Config     json.RawMessage `json:"config"`
	SecretEnc  []byte          `json:"-"`
	HasSecret  bool            `json:"has_secret"`
	Events     []string        `json:"events"`
	Enabled    bool            `json:"enabled"`
	CreatedAt  time.Time       `json:"created_at"`
	LastSentAt *time.Time      `json:"last_sent_at"`
	LastError  string          `json:"last_error"`
}

const channelColumns = `id, name, kind, config, secret_enc, events, enabled, created_at, last_sent_at, last_error`

func scanChannel(row interface{ Scan(...any) error }) (*Channel, error) {
	var c Channel
	if err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Config, &c.SecretEnc, &c.Events, &c.Enabled, &c.CreatedAt,
		&c.LastSentAt, &c.LastError); err != nil {
		return nil, notFound(err)
	}
	c.HasSecret = len(c.SecretEnc) > 0
	return &c, nil
}

// ListChannels, kanalları döner.
func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+channelColumns+` FROM notification_channels ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// GetChannel, kanalı döner.
func (s *Store) GetChannel(ctx context.Context, id string) (*Channel, error) {
	return scanChannel(s.pool.QueryRow(ctx, `SELECT `+channelColumns+` FROM notification_channels WHERE id = $1`, id))
}

// SaveChannel, kanalı ekler veya günceller; secretEnc nil ise mevcut gizli değer korunur.
func (s *Store) SaveChannel(ctx context.Context, c Channel, secretEnc []byte) (*Channel, error) {
	if c.ID == "" {
		return scanChannel(s.pool.QueryRow(ctx, `INSERT INTO notification_channels (name, kind, config, secret_enc, events, enabled)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+channelColumns,
			c.Name, c.Kind, c.Config, secretEnc, nonNilStrings(c.Events), c.Enabled))
	}
	return scanChannel(s.pool.QueryRow(ctx, `UPDATE notification_channels SET name = $2, kind = $3, config = $4,
		secret_enc = coalesce($5, secret_enc), events = $6, enabled = $7 WHERE id = $1 RETURNING `+channelColumns,
		c.ID, c.Name, c.Kind, c.Config, secretEnc, nonNilStrings(c.Events), c.Enabled))
}

// DeleteChannel, kanalı (ve zamanlanmış raporlarını) siler.
func (s *Store) DeleteChannel(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// ChannelResult, gönderim sonucunu yazar.
func (s *Store) ChannelResult(ctx context.Context, id string, at time.Time, sendErr error) error {
	msg := ""
	if sendErr != nil {
		msg = sendErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, err := s.pool.Exec(ctx, `UPDATE notification_channels SET last_sent_at = CASE WHEN $3 = '' THEN $2 ELSE last_sent_at END,
		last_error = $3 WHERE id = $1`, id, at, msg)
	return err
}

// ClaimEvent, olayı ilk kez kaydeder; daha önce kaydedildiyse false döner (tekrar bildirilmez).
func (s *Store) ClaimEvent(ctx context.Context, event, key string, payload any) (bool, error) {
	tag, err := s.pool.Exec(ctx, `INSERT INTO notification_events (event, dedupe_key, payload) VALUES ($1, $2, $3)
		ON CONFLICT (event, dedupe_key) DO NOTHING`, event, key, payload)
	return err == nil && tag.RowsAffected() == 1, err
}

// CompletedAction, bildirim için tamamlanmış aksiyondur.
type CompletedAction struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Kind      string         `json:"kind"`
	CreatedBy string         `json:"created_by"`
	Counts    map[string]int `json:"counts"`
}

// RecentlyCompletedActions, son iki saatte tamamlanan aksiyonları döner.
func (s *Store) RecentlyCompletedActions(ctx context.Context, now time.Time) ([]CompletedAction, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.name, a.kind, a.created_by_name,
		       coalesce((SELECT jsonb_object_agg(status, n) FROM (SELECT status, count(*) n FROM action_targets t
		                 WHERE t.action_id = a.id GROUP BY status) c), '{}')
		FROM actions a WHERE a.status = 'completed' AND a.completed_at > $1::timestamptz - interval '2 hours'`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CompletedAction
	for rows.Next() {
		var c CompletedAction
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.CreatedBy, &c.Counts); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// NewKEV, filoda bulunan ve yakın zamanda KEV kataloğuna eklenen açıktır.
type NewKEV struct {
	CVE       string    `json:"cve_id"`
	Name      string    `json:"name"`
	DateAdded time.Time `json:"date_added"`
	Affected  int       `json:"affected_machines"`
	Ransom    bool      `json:"ransomware"`
}

// RecentKEVInFleet, son 7 günde KEV'e eklenmiş ve aktif makinelerde bulunan açıkları döner.
func (s *Store) RecentKEVInFleet(ctx context.Context, now time.Time) ([]NewKEV, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT k.cve_id, k.name, k.date_added, count(DISTINCT mv.machine_id), k.ransomware
		FROM kev k JOIN machine_vulnerabilities mv ON mv.cve_id = k.cve_id
		JOIN machines m ON m.id = mv.machine_id AND m.status IN ('active', 'pending')
		WHERE k.date_added >= ($1::timestamptz - interval '7 days')::date
		GROUP BY k.cve_id, k.name, k.date_added, k.ransomware`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []NewKEV
	for rows.Next() {
		var k NewKEV
		if err := rows.Scan(&k.CVE, &k.Name, &k.DateAdded, &k.Affected, &k.Ransom); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// ReportSchedule, zamanlanmış rapordur.
type ReportSchedule struct {
	ID        string     `json:"id"`
	Report    string     `json:"report"`
	Format    string     `json:"format"`
	Lang      string     `json:"lang"`
	Weekday   *int16     `json:"weekday"`
	Hour      int16      `json:"hour"`
	Timezone  string     `json:"timezone"`
	ChannelID string     `json:"channel_id"`
	Enabled   bool       `json:"enabled"`
	LastRunAt *time.Time `json:"last_run_at"`
}

// ListSchedules, zamanlanmış raporları döner.
func (s *Store) ListSchedules(ctx context.Context) ([]ReportSchedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, report, format, lang, weekday, hour, timezone, channel_id, enabled, last_run_at
		FROM report_schedules ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportSchedule{}
	for rows.Next() {
		var r ReportSchedule
		if err := rows.Scan(&r.ID, &r.Report, &r.Format, &r.Lang, &r.Weekday, &r.Hour, &r.Timezone, &r.ChannelID, &r.Enabled,
			&r.LastRunAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateSchedule, zamanlanmış rapor ekler.
func (s *Store) CreateSchedule(ctx context.Context, r ReportSchedule) (string, error) {
	err := s.pool.QueryRow(ctx, `INSERT INTO report_schedules (report, format, lang, weekday, hour, timezone, channel_id, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
		r.Report, r.Format, r.Lang, r.Weekday, r.Hour, r.Timezone, r.ChannelID, r.Enabled).Scan(&r.ID)
	return r.ID, err
}

// DeleteSchedule, zamanlanmış raporu siler.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// MarkScheduleRun, raporun çalıştığını kaydeder.
func (s *Store) MarkScheduleRun(ctx context.Context, id string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE report_schedules SET last_run_at = $2 WHERE id = $1`, id, at)
	return err
}
