package store

import (
	"context"
	"time"
)

// MaintenanceWindow, bakım penceresidir.
type MaintenanceWindow struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Weekdays        []int16   `json:"weekdays"` // 0 = Pazar
	StartMinute     int16     `json:"start_minute"`
	DurationMinutes int       `json:"duration_minutes"`
	Timezone        string    `json:"timezone"`
	ScopeOUs        []string  `json:"scope_ous"`
	Enabled         bool      `json:"enabled"`
	CreatedAt       time.Time `json:"created_at"`
}

const windowColumns = `id, name, weekdays, start_minute, duration_minutes, timezone, scope_ous, enabled, created_at`

// ListWindows, bakım pencerelerini döner.
func (s *Store) ListWindows(ctx context.Context) ([]MaintenanceWindow, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+windowColumns+` FROM maintenance_windows ORDER BY lower(name)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MaintenanceWindow{}
	for rows.Next() {
		var w MaintenanceWindow
		if err := rows.Scan(&w.ID, &w.Name, &w.Weekdays, &w.StartMinute, &w.DurationMinutes, &w.Timezone, &w.ScopeOUs,
			&w.Enabled, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// SaveWindow, pencereyi ekler (ID boşsa) veya günceller.
func (s *Store) SaveWindow(ctx context.Context, w MaintenanceWindow) (string, error) {
	if w.ID == "" {
		err := s.pool.QueryRow(ctx, `INSERT INTO maintenance_windows (name, weekdays, start_minute, duration_minutes, timezone,
			scope_ous, enabled) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			w.Name, w.Weekdays, w.StartMinute, w.DurationMinutes, w.Timezone, nonNilStrings(w.ScopeOUs), w.Enabled).Scan(&w.ID)
		return w.ID, err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE maintenance_windows SET name = $2, weekdays = $3, start_minute = $4,
		duration_minutes = $5, timezone = $6, scope_ous = $7, enabled = $8 WHERE id = $1`,
		w.ID, w.Name, w.Weekdays, w.StartMinute, w.DurationMinutes, w.Timezone, nonNilStrings(w.ScopeOUs), w.Enabled)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return w.ID, err
}

// DeleteWindow, pencereyi siler.
func (s *Store) DeleteWindow(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM maintenance_windows WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	return err
}

// OpenWindowsFor, verilen zamanda pencere içinde olunup olunmadığını hesaplar. Makineye
// uyan etkin pencere yoksa her zaman açık sayılır (applies false döner).
func OpenWindowsFor(windows []MaintenanceWindow, machineOU string, now time.Time, inScope func(string, []string) bool) (open, applies bool) {
	for _, w := range windows {
		if !w.Enabled || !inScope(machineOU, w.ScopeOUs) {
			continue
		}
		applies = true
		if w.Contains(now) {
			return true, true
		}
	}
	return !applies, applies
}

// Contains, zamanın pencere içinde olup olmadığını döner. Gece yarısını aşan pencereler
// başladıkları güne aittir.
func (w MaintenanceWindow) Contains(t time.Time) bool {
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		loc = time.UTC
	}
	lt := t.In(loc)
	// Bugün ve dün başlayan pencereler denetlenir (gece yarısını aşan pencere için).
	for _, back := range []int{0, 1} {
		day := lt.AddDate(0, 0, -back)
		wd := int16(day.Weekday())
		match := false
		for _, d := range w.Weekdays {
			match = match || d == wd
		}
		if !match {
			continue
		}
		start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc).Add(time.Duration(w.StartMinute) * time.Minute)
		end := start.Add(time.Duration(w.DurationMinutes) * time.Minute)
		if !lt.Before(start) && lt.Before(end) {
			return true
		}
	}
	return false
}
