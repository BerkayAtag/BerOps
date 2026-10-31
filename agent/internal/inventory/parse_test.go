package inventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNormalizeUninstall(t *testing.T) {
	app, ok := NormalizeUninstall(UninstallEntry{
		KeyName: "{23170F69-40C1-2702-2301-000001000000}", DisplayName: " 7-Zip 23.01 (x64 edition) ", DisplayVersion: "23.01.00.0",
		Publisher: "Igor Pavlov", InstallDate: "20240115", WindowsInstaller: 1, Arch: "x64", Scope: "machine",
	})
	if !ok || app.Name != "7-Zip 23.01 (x64 edition)" || app.Source != protocol.AppSourceMSI ||
		app.InstallDate != "2024-01-15" || app.Identifier != "{23170F69-40C1-2702-2301-000001000000}" {
		t.Errorf("beklenmeyen uygulama: %+v %v", app, ok)
	}

	skip := []UninstallEntry{
		{DisplayName: ""},
		{DisplayName: "Microsoft Visual C++ Redistributable bileşeni", SystemComponent: 1},
		{DisplayName: "Office güncellemesi", ParentKeyName: "Office16.PROPLUS"},
		{DisplayName: "Security Update for Microsoft Office (KB5002623)"},
		{DisplayName: "Hotfix", ReleaseType: "Hotfix"},
	}
	for _, e := range skip {
		if _, ok := NormalizeUninstall(e); ok {
			t.Errorf("%+v uygulama sayılmamalı", e)
		}
	}
}

func TestNormalizeDate(t *testing.T) {
	cases := map[string]string{
		"20240115":             "2024-01-15",
		"2024-01-15":           "2024-01-15",
		"10/9/2024":            "2024-10-09",
		"09.10.2024":           "2024-10-09",
		"2024-10-09T00:00:00Z": "2024-10-09",
		"01cf2b9b0d0a4000":     "",
		"":                     "",
		"19000101":             "",
	}
	for in, want := range cases {
		if got := NormalizeDate(in); got != want {
			t.Errorf("NormalizeDate(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestParseWUAResult(t *testing.T) {
	patches, source, err := ParseWUAResult(readFixture(t, "wua.json"))
	if err != nil {
		t.Fatal(err)
	}
	if source != "online" || len(patches) != 2 {
		t.Fatalf("kaynak %q, %d yama", source, len(patches))
	}
	p := patches[0]
	if p.KB != "KB5046617" || p.Classification != "Security Updates" || p.Severity != "Critical" ||
		!p.RebootRequired || p.ReleasedAt == nil || p.ID != "6a8c2b1e-1111-4c3d-9e8f-0123456789ab" {
		t.Errorf("güvenlik güncellemesi: %+v", p)
	}
	if len(p.CVEs) != 2 || p.CVEs[0] != "CVE-2024-43451" || p.CVEs[1] != "CVE-2024-49039" {
		t.Errorf("CVE'ler tekilleştirilip büyük harfe çevrilmeli: %v", p.CVEs)
	}
	if patches[1].Classification != "Definition Updates" {
		t.Errorf("yerelleştirilmiş sınıflandırma GUID ile İngilizceye çevrilmeli: %q", patches[1].Classification)
	}
	if _, _, err := ParseWUAResult([]byte("PowerShell hatası")); err == nil {
		t.Error("JSON olmayan çıktı hata vermeli")
	}
}

func TestParseSystemInfo(t *testing.T) {
	si, err := ParseSystemInfo(readFixture(t, "system.json"))
	if err != nil {
		t.Fatal(err)
	}
	hf := si.HotfixPatches()
	if len(hf) != 2 || hf[0].ID != "KB5044284" || hf[0].InstalledOn != "2024-10-09" || hf[1].ID != "KB5043113" {
		t.Errorf("KB listesi: %+v", hf)
	}
	appx := si.AppXApps()
	if len(appx) != 1 || appx[0].Publisher != "Microsoft Corporation" || appx[0].Arch != "x64" || appx[0].Source != protocol.AppSourceAppX {
		t.Errorf("AppX: %+v", appx)
	}
	if si.Memory != 34359738368 || !si.PartOfDomain {
		t.Errorf("sistem bilgisi: %+v", si)
	}
}

func TestParseSoftwareUpdateList(t *testing.T) {
	ps := ParseSoftwareUpdateList(string(readFixture(t, "softwareupdate_list.txt")))
	if len(ps) != 3 {
		t.Fatalf("3 güncelleme beklenirdi: %+v", ps)
	}
	if ps[0].ID != "macOS Sequoia 15.1.1-24B91" || ps[0].Version != "15.1.1" || !ps[0].RebootRequired ||
		!ps[0].Recommended || ps[0].SizeBytes != 1659427*1024 || ps[0].Classification != "macOS" {
		t.Errorf("macOS güncellemesi: %+v", ps[0])
	}
	if ps[1].Title != "Safari" || ps[1].RebootRequired || ps[1].Classification != "Application" {
		t.Errorf("Safari: %+v", ps[1])
	}
	if ps[2].SizeBytes != 1024000*1024 {
		t.Errorf("K birimi: %+v", ps[2])
	}
	if got := ParseSoftwareUpdateList("Software Update Tool\n\nFinding available software\nNo new software available.\n"); len(got) != 0 {
		t.Errorf("güncelleme yoksa boş liste: %+v", got)
	}
}

func TestParseInfoPlistXMLAndBinary(t *testing.T) {
	src := map[string]any{
		"CFBundleName":               "Chrome",
		"CFBundleDisplayName":        "Google Chrome",
		"CFBundleShortVersionString": "130.0.6723.92",
		"CFBundleIdentifier":         "com.google.Chrome",
		"NSHumanReadableCopyright":   "Copyright 2024 Google LLC. All rights reserved.",
	}
	for _, format := range []int{plist.XMLFormat, plist.BinaryFormat} {
		data, err := plist.Marshal(src, format)
		if err != nil {
			t.Fatal(err)
		}
		app, err := ParseInfoPlist(data, "/Applications/Google Chrome.app")
		if err != nil {
			t.Fatal(err)
		}
		if app.Name != "Google Chrome" || app.Version != "130.0.6723.92" || app.Identifier != "com.google.Chrome" ||
			app.Publisher != "Google LLC" || app.Source != protocol.AppSourceAppBundle {
			t.Errorf("biçim %d: %+v", format, app)
		}
	}
}

func TestPublisherFromCopyright(t *testing.T) {
	cases := map[string]string{
		"Copyright © 2010-2024 Mozilla Corporation. All rights reserved.": "Mozilla Corporation",
		"© 2024 Zoom Video Communications, Inc.":                          "Zoom Video Communications, Inc",
		"(c) 2003 - present, VideoLAN":                                    "VideoLAN",
		"":                                                                "",
	}
	for in, want := range cases {
		if got := publisherFromCopyright(in); got != want {
			t.Errorf("publisherFromCopyright(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestParseReceipt(t *testing.T) {
	data, _ := plist.Marshal(map[string]any{
		"PackageIdentifier": "us.zoom.pkg.videomeeting", "PackageVersion": "6.2.5.41699",
		"InstallDate": time.Date(2024, 10, 1, 12, 0, 0, 0, time.UTC), "InstallPrefixPath": "/",
	}, plist.BinaryFormat)
	app, ok := ParseReceipt(data)
	if !ok || app.Version != "6.2.5.41699" || app.InstallDate != "2024-10-01" || app.Source != protocol.AppSourcePkg {
		t.Errorf("paket makbuzu: %+v %v", app, ok)
	}
	apple, _ := plist.Marshal(map[string]any{"PackageIdentifier": "com.apple.pkg.CLTools_Executables"}, plist.XMLFormat)
	if _, ok := ParseReceipt(apple); ok {
		t.Error("Apple paketleri atlanmalı")
	}
}

func TestParseInstallHistory(t *testing.T) {
	ps, err := ParseInstallHistory(readFixture(t, "InstallHistory.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) != 2 || ps[0].ID != "macOS Sequoia 15.1 15.1" || ps[0].InstalledOn != "2024-10-29" {
		t.Errorf("yalnızca Apple güncellemeleri alınmalı: %+v", ps)
	}
}

func TestScanHomebrew(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"git/2.46.0", "git/2.47.1", "git/2.9.0", "openssl@3/3.4.0", ".keep", "bos"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	apps := ScanHomebrew(root, protocol.AppSourceHomebrew)
	if len(apps) != 2 {
		t.Fatalf("2 formül beklenirdi: %+v", apps)
	}
	if apps[0].Name != "git" || apps[0].Version != "2.47.1" {
		t.Errorf("en yüksek sürüm seçilmeli (sayısal karşılaştırma): %+v", apps[0])
	}
	if ScanHomebrew(filepath.Join(root, "yok"), "x") != nil {
		t.Error("olmayan dizin boş dönmeli")
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.10", "1.9", 1}, {"2.47.1", "2.47.1", 0}, {"130.0.6723.92", "130.0.6723.117", -1},
		{"1.0", "1.0.1", -1}, {"1.0-beta", "1.0", 1}, {"24.08", "23.01", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, beklenen %d", c.a, c.b, got, c.want)
		}
	}
}

func TestSortAndDedupeApps(t *testing.T) {
	apps := []protocol.App{
		{Name: "zoom", Version: "6.2", Source: "app_bundle"},
		{Name: "7-Zip", Version: "23.01", Source: "msi", Scope: "machine"},
		{Name: "7-zip", Version: "23.01", Source: "msi", Scope: "machine"},
		{Name: "7-Zip", Version: "23.01", Source: "registry", Scope: "user:S-1"},
	}
	out := SortAndDedupeApps(apps)
	if len(out) != 3 || out[0].Name != "7-Zip" || out[2].Name != "zoom" {
		t.Errorf("sıralama ve tekilleştirme: %+v", out)
	}
	// Aynı içerik farklı sırada gelse de özet aynı olmalı.
	again := SortAndDedupeApps([]protocol.App{out[2], out[1], out[0]})
	if protocol.HashSection(again) != protocol.HashSection(out) {
		t.Error("sıra özeti etkilememeli")
	}
}
