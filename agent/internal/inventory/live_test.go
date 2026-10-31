package inventory

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestLiveCollect, bu makinede gerçek toplama yapar. Yavaş olabileceği için yalnızca
// BER_LIVE_INVENTORY=1 tanımlıysa çalışır (BER_LIVE_INVENTORY=full eksik yamaları da tarar).
func TestLiveCollect(t *testing.T) {
	mode := os.Getenv("BER_LIVE_INVENTORY")
	if mode == "" {
		t.Skip("BER_LIVE_INVENTORY tanımlı değil")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	s := Collect(ctx, Options{CPULimitPercent: 10, IncludeMissing: mode == "full"})
	t.Logf("süre: %v, bölümler: %v, hatalar: %v", s.Duration, s.Collected, s.Errors)
	t.Logf("işletim sistemi: %+v", *s.OS)
	t.Logf("uygulama: %d, kurulu yama: %d, eksik yama: %d", len(s.Apps), len(s.InstalledPatches), len(s.MissingPatches))
	for i, a := range s.Apps {
		if i >= 8 {
			break
		}
		t.Logf("  %s %s [%s] %s", a.Name, a.Version, a.Source, a.Publisher)
	}
	for _, p := range s.MissingPatches {
		t.Logf("  eksik: %s (%s) yeniden başlatma=%v", p.Title, p.Version, p.RebootRequired)
	}
	if !s.Collected["os"] || !s.Collected["apps"] {
		t.Error("os ve apps bölümleri toplanmalı")
	}
}
