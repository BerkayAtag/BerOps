package store_test

import (
	"testing"
	"time"
	_ "time/tzdata"

	"github.com/BerkayAtag/BerOps/server/internal/store"
)

func TestMaintenanceWindowContains(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	// Pazar 03:00-05:00 (Berlin). 2026-03-29 yaz saatine geçiş günüdür (02:00 → 03:00).
	w := store.MaintenanceWindow{Weekdays: []int16{0}, StartMinute: 3 * 60, DurationMinutes: 120,
		Timezone: "Europe/Berlin", Enabled: true}
	cases := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 3, 29, 3, 0, 0, 0, berlin), true},
		{time.Date(2026, 3, 29, 4, 59, 0, 0, berlin), true},
		{time.Date(2026, 3, 29, 5, 0, 0, 0, berlin), false},
		{time.Date(2026, 3, 29, 1, 59, 0, 0, berlin), false},
		{time.Date(2026, 3, 22, 3, 30, 0, 0, berlin), true},
		{time.Date(2026, 3, 23, 3, 30, 0, 0, berlin), false},
	}
	for _, c := range cases {
		if got := w.Contains(c.at); got != c.want {
			t.Errorf("%s: %v bekleniyordu, %v bulundu", c.at, c.want, got)
		}
	}

	// Gece yarısını aşan pencere başladığı güne aittir: Cumartesi 23:00 + 3 saat.
	night := store.MaintenanceWindow{Weekdays: []int16{6}, StartMinute: 23 * 60, DurationMinutes: 180,
		Timezone: "UTC", Enabled: true}
	if !night.Contains(time.Date(2026, 11, 8, 1, 30, 0, 0, time.UTC)) {
		t.Error("Pazar 01:30, Cumartesi başlayan pencerenin içinde olmalı")
	}
	if night.Contains(time.Date(2026, 11, 9, 1, 30, 0, 0, time.UTC)) {
		t.Error("Pazartesi 01:30 pencerenin dışında olmalı")
	}
}
