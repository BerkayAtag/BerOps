package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/server/internal/store/storetest"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func TestOUFromDN(t *testing.T) {
	cases := map[string]string{
		"CN=PC01,OU=İzmir,OU=Şubeler,DC=corp,DC=example": "OU=İzmir,OU=Şubeler,DC=corp,DC=example",
		`CN=Kaya\, Deniz,OU=IT,DC=corp`:                  "OU=IT,DC=corp",
		"":                                               "",
		"CN=yalniz":                                      "",
	}
	for in, want := range cases {
		if got := store.OUFromDN(in); got != want {
			t.Errorf("OUFromDN(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func newMachine(t *testing.T, s *store.Store, id, hostname, platform string) {
	t.Helper()
	ctx := context.Background()
	k, err := s.CreateRegistrationKey(ctx, store.NewRegistrationKey{Name: "t", KeyHash: []byte(id), KeyPrefix: "x"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.CreateMachine(ctx, store.NewMachine{
		ID: id, Status: "active", Host: protocol.HostInfo{Hostname: hostname, OSPlatform: platform, IPAddresses: []string{"10.1.2.3"}},
		CertSerial: "1", CertFingerprint: "f", CertExpiresAt: now.Add(time.Hour), RegistrationKeyID: k.ID, EnrolledAt: now,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestApplyInventoryFullThenDelta(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	const id = "11111111-1111-4111-8111-111111111111"
	newMachine(t, s, id, "PC-01", "windows")

	now := time.Now().UTC().Truncate(time.Second)
	full := &protocol.InventoryReport{
		Full: true, CollectedAt: now, Included: protocol.AllSections,
		Hashes: map[string]string{"os": "h-os", "installed_patches": "h-ip", "missing_patches": "h-mp", "apps": "h-app"},
		OS:     &protocol.OSInventory{Platform: "windows", Build: "10.0.22631.4460", ADDN: "CN=PC-01,OU=İzmir,DC=corp,DC=example", RebootPending: true},
		InstalledPatches: []protocol.InstalledPatch{
			{ID: "KB5044284", InstalledOn: "2024-10-09", Source: "hotfix"},
			{ID: "KB5044284", InstalledOn: "2024-10-09", Source: "hotfix"}, // yinelenen kayıt yok sayılmalı
		},
		MissingPatches: []protocol.MissingPatch{
			{ID: "u1", KB: "KB5046617", Title: "2024-11 Cumulative", Classification: "Security Updates", Severity: "Critical", CVEs: []string{"CVE-2024-43451"}},
			{ID: "u2", Title: "Defender tanım güncellemesi", Classification: "Definition Updates"},
		},
		MissingScan: &protocol.MissingScanInfo{Source: protocol.ScanSourceOnline, ScannedAt: now},
		Apps: []protocol.App{
			{Name: "7-Zip 23.01 (x64)", Version: "23.01", Publisher: "Igor Pavlov", Source: "registry", InstallDate: "2024-01-15"},
			{Name: "Google Chrome", Version: "130.0.6723.92", Source: "msi"},
		},
	}
	if err := s.ApplyInventory(ctx, id, full, now); err != nil {
		t.Fatal(err)
	}
	sum, err := s.GetInventorySummary(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if sum.MissingCount != 2 || sum.MissingCriticalCount != 1 || sum.MissingSecurityCount != 1 ||
		sum.InstalledPatchCount != 1 || sum.AppCount != 2 || !sum.RebootPending || sum.LastFullAt == nil {
		t.Errorf("beklenmeyen özet: %+v", sum)
	}
	m, _ := s.GetMachine(ctx, id)
	if m.ADOU != "OU=İzmir,DC=corp,DC=example" {
		t.Errorf("AD OU çıkarılmalı: %q", m.ADOU)
	}

	// Delta: yalnızca uygulamalar değişti. Eksik yamalar korunmalı.
	delta := &protocol.InventoryReport{
		CollectedAt: now.Add(4 * time.Hour), Included: []string{protocol.SectionApps},
		Hashes: map[string]string{"apps": "h-app-2"},
		Apps:   []protocol.App{{Name: "7-Zip 24.08 (x64)", Version: "24.08", Source: "registry"}},
	}
	if err := s.ApplyInventory(ctx, id, delta, now.Add(4*time.Hour)); err != nil {
		t.Fatal(err)
	}
	sum, _ = s.GetInventorySummary(ctx, id)
	if sum.AppCount != 1 || sum.MissingCount != 2 || sum.Hashes["apps"] != "h-app-2" || sum.Hashes["missing_patches"] != "h-mp" {
		t.Errorf("delta yalnızca uygulamaları değiştirmeli: %+v", sum)
	}
	if sum.OS == nil || sum.OS.Build != "10.0.22631.4460" {
		t.Error("delta'da gönderilmeyen işletim sistemi bilgisi korunmalı")
	}
	missing, _ := s.ListMissingPatches(ctx, id)
	if len(missing) != 2 || missing[0].Severity != "Critical" || missing[0].CVEs[0] != "CVE-2024-43451" {
		t.Errorf("eksik yamalar önem sırasıyla dönmeli: %+v", missing)
	}

	st, err := s.GetInventoryState(ctx, id)
	if err != nil || !st.HasInventory || st.Hashes["apps"] != "h-app-2" {
		t.Errorf("envanter durumu yanlış: %+v %v", st, err)
	}
}

func TestScanRequestClearedByFullInventory(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	const id = "22222222-2222-4222-8222-222222222222"
	newMachine(t, s, id, "MAC-01", "darwin")
	now := time.Now()
	n, err := s.RequestScan(ctx, []string{id}, now)
	if err != nil || n != 1 {
		t.Fatalf("tarama isteği kaydedilmeli: %d %v", n, err)
	}
	st, _ := s.GetInventoryState(ctx, id)
	if st.ScanRequestedAt == nil || st.HasInventory {
		t.Fatalf("beklenmeyen durum: %+v", st)
	}
	r := &protocol.InventoryReport{Full: true, CollectedAt: now, Included: []string{protocol.SectionApps},
		Hashes: map[string]string{"apps": "x"}, Apps: []protocol.App{}}
	if err := s.ApplyInventory(ctx, id, r, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	st, _ = s.GetInventoryState(ctx, id)
	if st.ScanRequestedAt != nil {
		t.Error("tam envanter tarama isteğini temizlemeli")
	}
}

func TestListMachinesFiltered(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	newMachine(t, s, "33333333-3333-4333-8333-333333333331", "WIN-ALFA", "windows")
	newMachine(t, s, "33333333-3333-4333-8333-333333333332", "WIN-BETA", "windows")
	newMachine(t, s, "33333333-3333-4333-8333-333333333333", "MAC-GAMA", "darwin")
	now := time.Now()
	// WIN-BETA'da 3 eksik yama.
	r := &protocol.InventoryReport{Full: true, CollectedAt: now, Included: []string{protocol.SectionMissingPatches},
		Hashes:         map[string]string{"missing_patches": "x"},
		MissingScan:    &protocol.MissingScanInfo{Source: "online", ScannedAt: now},
		MissingPatches: []protocol.MissingPatch{{ID: "a", Title: "a"}, {ID: "b", Title: "b"}, {ID: "c", Title: "c"}}}
	if err := s.ApplyInventory(ctx, "33333333-3333-4333-8333-333333333332", r, now); err != nil {
		t.Fatal(err)
	}

	base := store.MachineFilter{Now: now, OnlineWindow: time.Hour, Limit: 50}

	f := base
	f.Platform = "windows"
	items, total, err := s.ListMachinesFiltered(ctx, f)
	if err != nil || total != 2 || len(items) != 2 {
		t.Fatalf("platform filtresi: %d %v", total, err)
	}

	f = base
	f.Search = "gama"
	items, total, _ = s.ListMachinesFiltered(ctx, f)
	if total != 1 || items[0].Hostname != "MAC-GAMA" {
		t.Errorf("arama hostname'de büyük/küçük harf duyarsız olmalı: %+v", items)
	}

	f = base
	f.Search = "10.1.2"
	_, total, _ = s.ListMachinesFiltered(ctx, f)
	if total != 3 {
		t.Errorf("IP ile arama tüm makineleri bulmalı: %d", total)
	}

	f = base
	f.Search = "%"
	_, total, _ = s.ListMachinesFiltered(ctx, f)
	if total != 0 {
		t.Errorf("LIKE özel karakterleri kaçışlanmalı: %d", total)
	}

	f = base
	f.Sort, f.Desc = "missing_count", true
	items, _, _ = s.ListMachinesFiltered(ctx, f)
	if items[0].Hostname != "WIN-BETA" || items[0].MissingCount != 3 {
		t.Errorf("eksik yama sayısına göre azalan sıralama: %+v", items[0])
	}

	f = base
	f.Sort, f.Limit, f.Offset = "hostname", 2, 2
	items, total, _ = s.ListMachinesFiltered(ctx, f)
	if total != 3 || len(items) != 1 || items[0].Hostname != "WIN-BETA" {
		t.Errorf("sayfalama: toplam %d, sayfa %+v", total, items)
	}

	f = base
	f.Sort = "hostname; DROP TABLE machines" // bilinmeyen sıralama varsayılana düşmeli
	if _, _, err := s.ListMachinesFiltered(ctx, f); err != nil {
		t.Errorf("bilinmeyen sıralama alanı hata vermemeli: %v", err)
	}

	online := true
	f = base
	f.Online = &online
	_, total, _ = s.ListMachinesFiltered(ctx, f)
	if total != 3 {
		t.Errorf("yeni kaydolan makineler çevrimiçi sayılmalı: %d", total)
	}

	sum, err := s.GetFleetSummary(ctx, now, time.Hour)
	if err != nil || sum.Total != 3 || sum.Windows != 2 || sum.MacOS != 1 || sum.MissingTotal != 3 {
		t.Errorf("filo özeti: %+v %v", sum, err)
	}
}

func TestAgentSettingsDefaultsAndSave(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	set, err := s.GetAgentSettings(ctx)
	if err != nil || set != protocol.DefaultAgentSettings() {
		t.Fatalf("kayıt yokken varsayılanlar dönmeli: %+v %v", set, err)
	}
	set.ScanCPULimitPercent = 25
	if err := s.SaveAgentSettings(ctx, set, ""); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetAgentSettings(ctx)
	if got.ScanCPULimitPercent != 25 {
		t.Errorf("kaydedilen ayar okunmalı: %+v", got)
	}
}
