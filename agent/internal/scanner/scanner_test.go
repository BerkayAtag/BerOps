package scanner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/agent/internal/inventory"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

type fakeClient struct {
	fail      bool
	reports   []*protocol.InventoryReport
	cabCalls  int
	cabFailed bool
}

func (f *fakeClient) UploadInventory(_ context.Context, r *protocol.InventoryReport) error {
	if f.fail {
		return errors.New("sunucuya ulaşılamadı")
	}
	f.reports = append(f.reports, r)
	return nil
}

func (f *fakeClient) DownloadWSUSCab(context.Context, string) error {
	f.cabCalls++
	if f.cabFailed {
		return errors.New("404")
	}
	return nil
}

type harness struct {
	s       *Scanner
	client  *fakeClient
	now     time.Time
	apps    []protocol.App
	collect []inventory.Options
	battery bool
}

func newHarness(t *testing.T) *harness {
	h := &harness{client: &fakeClient{}, now: time.Date(2026, 1, 5, 9, 0, 0, 0, time.UTC),
		apps: []protocol.App{{Name: "7-Zip", Version: "23.01", Source: "msi"}}}
	s := New(t.TempDir(), protocol.PlatformWindows, h.client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.now = func() time.Time { return h.now }
	s.rnd = func() float64 { return 0.5 } // sapmasız
	s.OnBattery = func() (bool, error) { return h.battery, nil }
	s.Collect = func(_ context.Context, opts inventory.Options) *inventory.Snapshot {
		h.collect = append(h.collect, opts)
		snap := &inventory.Snapshot{
			OS:        &protocol.OSInventory{Platform: "windows", Build: "10.0.22631.4460"},
			Apps:      append([]protocol.App(nil), h.apps...),
			Collected: map[string]bool{"os": true, "apps": true, "installed_patches": true},
		}
		if opts.IncludeMissing {
			snap.MissingPatches = []protocol.MissingPatch{{ID: "u1", Title: "KB5046617"}}
			snap.MissingScan = &protocol.MissingScanInfo{Source: "online", ScannedAt: h.now}
			snap.Collected["missing_patches"] = true
		}
		return snap
	}
	if err := s.Load(); err != nil {
		t.Fatal(err)
	}
	h.s = s
	return h
}

func (h *harness) advance(d time.Duration) { h.now = h.now.Add(d) }

func TestFirstFullScanThenDeltaOnlyWhenChanged(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// İlk tam tarama, kayıttan sonra en fazla 5 dk içinde (rnd=0.5 → 2,5 dk).
	if wait := h.s.Step(ctx); wait != 150*time.Second || len(h.collect) != 0 {
		t.Fatalf("ilk tarama beklenmeli: bekleme %v, toplama %d", wait, len(h.collect))
	}
	h.advance(150 * time.Second)
	h.s.Step(ctx)
	if len(h.client.reports) != 1 || !h.client.reports[0].Full || len(h.client.reports[0].Included) != 4 {
		t.Fatalf("ilk tam envanter tüm bölümleri içermeli: %+v", h.client.reports)
	}
	if !h.collect[0].IncludeMissing || h.collect[0].CPULimitPercent != 10 {
		t.Errorf("tam tarama eksik yamaları içermeli ve CPU sınırını uygulamalı: %+v", h.collect[0])
	}
	if got := h.s.UploadedHashes(); len(got) != 4 {
		t.Errorf("heartbeat'e eklenecek özetler: %v", got)
	}

	// 4 saat sonra değişiklik taraması: hiçbir şey değişmediyse yükleme yapılmaz.
	h.advance(4 * time.Hour)
	h.s.Step(ctx)
	if len(h.collect) != 2 || h.collect[1].IncludeMissing {
		t.Fatalf("değişiklik taraması eksik yama taraması yapmamalı: %+v", h.collect)
	}
	if len(h.client.reports) != 1 {
		t.Errorf("değişiklik yokken yükleme yapılmamalı: %d", len(h.client.reports))
	}

	// Uygulama güncellendi: yalnızca apps bölümü gönderilir.
	h.apps[0].Version = "24.08"
	h.advance(4 * time.Hour)
	h.s.Step(ctx)
	last := h.client.reports[len(h.client.reports)-1]
	if last.Full || len(last.Included) != 1 || last.Included[0] != "apps" || last.Apps[0].Version != "24.08" {
		t.Errorf("yalnızca değişen bölüm gönderilmeli: %+v", last)
	}
	if len(last.Hashes) != 4 {
		t.Error("rapor tüm bölümlerin güncel özetlerini taşımalı")
	}
}

func TestFailedUploadIsRetried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.client.fail = true
	h.advance(10 * time.Minute)
	h.s.Step(ctx)
	if len(h.client.reports) != 0 || h.s.UploadedHashes() != nil {
		t.Fatal("başarısız yükleme kaydedilmemeli")
	}
	if wait := h.s.Step(ctx); wait != retryDelay {
		t.Errorf("yeniden deneme %v sonra olmalı, %v", retryDelay, wait)
	}
	h.client.fail = false
	h.advance(retryDelay)
	h.s.Step(ctx)
	if len(h.client.reports) != 1 || len(h.client.reports[0].Included) != 4 || len(h.collect) != 1 {
		t.Errorf("yeniden deneme tekrar taramadan bekleyen bölümleri göndermeli: %d rapor, %d toplama",
			len(h.client.reports), len(h.collect))
	}
}

func TestServerRequestsFullResendFromCache(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.advance(10 * time.Minute)
	h.s.Step(ctx)

	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{RequestFullInventory: true})
	h.s.Step(ctx)
	if len(h.client.reports) != 2 || !h.client.reports[1].Full || len(h.collect) != 1 {
		t.Errorf("tam envanter önbellekten, yeniden taramadan gönderilmeli: %d rapor, %d toplama",
			len(h.client.reports), len(h.collect))
	}
}

func TestConsoleScanRequestIsHandledOnce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.advance(10 * time.Minute)
	h.s.Step(ctx)

	req := h.now.Add(time.Minute)
	h.advance(2 * time.Minute)
	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{ScanRequestedAt: &req})
	h.s.Step(ctx)
	if len(h.collect) != 2 || !h.collect[1].IncludeMissing {
		t.Fatalf("konsol isteği tam tarama başlatmalı: %+v", h.collect)
	}
	// Aynı istek sonraki heartbeat'te tekrar gelse de ikinci kez işlenmez.
	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{ScanRequestedAt: &req})
	h.s.Step(ctx)
	if len(h.collect) != 2 {
		t.Errorf("aynı istek bir kez işlenmeli: %d toplama", len(h.collect))
	}
}

func TestDeferOnBatteryUntilLimit(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.battery = true
	h.advance(10 * time.Minute)
	if wait := h.s.Step(ctx); wait != deferStep || len(h.collect) != 0 {
		t.Fatalf("pildeyken tarama ertelenmeli: bekleme %v, toplama %d", wait, len(h.collect))
	}
	h.advance(maxDefer)
	h.s.Step(ctx)
	if len(h.collect) != 1 {
		t.Error("en fazla erteleme süresinden sonra tarama yapılmalı")
	}

	// Konsoldan istenen tarama pil durumunda bile hemen yapılır.
	req := h.now
	h.advance(time.Minute)
	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{ScanRequestedAt: &req})
	h.s.Step(ctx)
	if len(h.collect) != 2 {
		t.Error("konsol isteği ertelenmemeli")
	}
}

func TestSettingsChangeAndOfflineCab(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	set := protocol.DefaultAgentSettings()
	set.ScanCPULimitPercent = 5
	set.WindowsUpdateSource = protocol.ScanSourceOffline
	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{Settings: &set})

	h.advance(10 * time.Minute)
	h.s.Step(ctx)
	if h.client.cabCalls != 1 || h.collect[0].WSUSCabPath == "" || h.collect[0].CPULimitPercent != 5 {
		t.Errorf("çevrimdışı modda katalog indirilmeli ve yeni CPU sınırı uygulanmalı: %+v", h.collect[0])
	}

	// Katalog indirilemezse eksik yama taraması atlanır ama diğer bölümler gönderilir.
	h.client.cabFailed = true
	req := h.now
	h.advance(time.Minute)
	h.s.ApplyHeartbeat(&protocol.HeartbeatResponse{ScanRequestedAt: &req})
	h.s.Step(ctx)
	if h.collect[1].IncludeMissing {
		t.Error("katalog yoksa eksik yama taraması yapılmamalı")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.advance(10 * time.Minute)
	h.s.Step(ctx)

	again := New(h.s.Dir, protocol.PlatformWindows, h.client, h.s.Log)
	again.now = h.s.now
	again.rnd = h.s.rnd
	if err := again.Load(); err != nil {
		t.Fatal(err)
	}
	if len(again.UploadedHashes()) != 4 {
		t.Error("yeniden başlatmadan sonra yüklenen özetler korunmalı")
	}
	if wait := again.Step(ctx); wait < 3*time.Hour {
		t.Errorf("yeniden başlatma hemen yeni tarama başlatmamalı: %v", wait)
	}
}
