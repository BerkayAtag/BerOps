package cve

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2", "1.2.0", 0},
		{"1.10", "1.9", 1},
		{"120.0.6099.109", "120.0.6099.71", 1},
		{"24.08", "26.01", -1},
		{"1.0", "1.0rc1", 1},
		{"1.0.1", "1.0rc1", 1},
		{"1.0beta", "1.0rc", -1},
		{"10.0.22631.4460", "10.0.22631.7652", -1},
		{"15.1", "15.0.1", 1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, beklenen %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, beklenen %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	for in, want := range map[string]string{
		"v2.45.2":           "2.45.2",
		"3.4.0_1":           "3.4.0",
		" 24.08 ":           "24.08",
		"Version 8.6.0 (x)": "8.6.0",
		"latest":            "",
	} {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestVersionRange(t *testing.T) {
	r := VersionRange{StartIncluding: "9.34", EndExcluding: "26.01"}
	for v, want := range map[string]bool{"9.34": true, "24.08": true, "26.01": false, "9.20": false, "": false} {
		if got := r.Contains(v); got != want {
			t.Errorf("Contains(%q) = %v, beklenen %v", v, got, want)
		}
	}
	if r.FixedIn() != ">= 26.01" {
		t.Errorf("FixedIn = %q", r.FixedIn())
	}
	if !(VersionRange{Exact: "4.43"}).Contains("4.43.0") || (VersionRange{Exact: "4.43"}).Contains("4.44") {
		t.Error("tam sürüm eşleşmesi hatalı")
	}
	if !(VersionRange{}).Contains("1.0") {
		t.Error("sınırsız aralık tüm sürümleri içermeli")
	}
}

func TestMatcherBuiltin(t *testing.T) {
	m, err := NewMatcher(nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := func(a AppRef) []string {
		var out []string
		for _, r := range m.MatchApp(a) {
			out = append(out, r.Key())
		}
		return out
	}
	cases := map[AppRef][]string{
		{Name: "Google Chrome"}:                      {"a:google:chrome"},
		{Name: "Mozilla Firefox ESR (x64 tr)"}:       {"a:mozilla:firefox_esr"},
		{Name: "Mozilla Firefox (x64 tr)"}:           {"a:mozilla:firefox"},
		{Name: "Firefox"}:                            {"a:mozilla:firefox"},
		{Name: "7-Zip 24.08 (x64)"}:                  {"a:7-zip:7-zip"},
		{Name: "Notepad++ (64-bit x64)"}:             {"a:notepad-plus-plus:notepad\\+\\+"},
		{Name: "zoom.us"}:                            {"a:zoom:workplace_desktop", "a:zoom:meetings", "a:zoom:zoom"},
		{Name: "openssl@3", Identifier: "openssl@3"}: {"a:openssl:openssl"},
		{Name: "Microsoft Edge WebView2 Runtime"}:    nil,
		{Name: "Bilinmeyen Uygulama"}:                nil,
	}
	for app, want := range cases {
		if got := keys(app); !slices.Equal(got, want) {
			t.Errorf("%q → %v, beklenen %v", app.Name, got, want)
		}
	}
	if r, ok := m.MatchOS("darwin"); !ok || r.Key() != "o:apple:macos" {
		t.Errorf("macOS kuralı = %v %v", r, ok)
	}
	if _, ok := m.MatchOS("windows"); ok {
		t.Error("Windows için NVD işletim sistemi kuralı olmamalı")
	}
}

func TestMatcherCustomFirst(t *testing.T) {
	m, err := NewMatcher([]ProductRule{{Name: "^google chrome$", Vendor: "ozel", Product: "tarayici"}})
	if err != nil {
		t.Fatal(err)
	}
	got := m.MatchApp(AppRef{Name: "Google Chrome"})
	if len(got) != 1 || got[0].Key() != "a:ozel:tarayici" {
		t.Errorf("özel kural yerleşik sözlükten önce gelmeli: %v", got)
	}
	for _, bad := range []ProductRule{
		{Name: "(", Vendor: "a", Product: "b"},
		{Name: "x", Vendor: "A B", Product: "b"},
		{Vendor: "a", Product: "b"},
	} {
		if ValidateRule(bad) == nil {
			t.Errorf("geçersiz kural kabul edildi: %+v", bad)
		}
	}
}

func TestRiskScore(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	cases := []struct {
		m    Meta
		want float64
	}{
		{Meta{CVSS: f(9.8)}, 58.8},
		{Meta{CVSS: f(9.8), EPSS: f(0.97), KEV: true, Ransomware: true}, 100},
		{Meta{CVSS: f(5.5), EPSS: f(0.5), KEV: true}, 60.5},
		{Meta{Severity: "Important"}, 45},
		{Meta{}, 30},
	}
	for _, c := range cases {
		if got := RiskScore(c.m); got != c.want {
			t.Errorf("RiskScore(%+v) = %v, beklenen %v", c.m, got, c.want)
		}
	}
	if RiskLevel(85) != RiskUrgent || RiskLevel(60) != RiskHigh || RiskLevel(45) != RiskMedium || RiskLevel(10) != RiskLow {
		t.Error("risk düzeyleri hatalı")
	}
}

func TestParseNVD(t *testing.T) {
	f, err := os.Open("testdata/nvd_7zip.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	page, recs, err := ParseNVD(f)
	if err != nil {
		t.Fatal(err)
	}
	if page.TotalResults != 3 || len(recs) != 3 {
		t.Fatalf("toplam %d, kayıt %d", page.TotalResults, len(recs))
	}
	var r *Record
	for i := range recs {
		if recs[i].ID == "CVE-2026-48112" {
			r = &recs[i]
		}
	}
	if r == nil {
		t.Fatal("CVE-2026-48112 bulunamadı")
	}
	if r.Description == "" || r.Published == nil || r.Source != "nvd" {
		t.Errorf("eksik alan: %+v", r)
	}
	want := ProductMatch{Part: "a", Vendor: "7-zip", Product: "7-zip", Range: VersionRange{StartIncluding: "9.34", EndExcluding: "26.01"}}
	if !slices.Contains(r.Matches, want) {
		t.Errorf("eşleşmeler = %+v", r.Matches)
	}
}

func TestParseNVDExactVersions(t *testing.T) {
	doc := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2013-6639","configurations":[{"nodes":[{"cpeMatch":[
		{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*","versionEndIncluding":"31.0.1650.62"},
		{"vulnerable":true,"criteria":"cpe:2.3:a:google:chrome:31.0.1650.0:*:*:*:*:*:*:*"},
		{"vulnerable":false,"criteria":"cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"}]}]}]}}]}`
	_, recs, err := ParseNVD(strings.NewReader(doc))
	if err != nil || len(recs) != 1 {
		t.Fatal(err)
	}
	want := []ProductMatch{
		{Part: "a", Vendor: "google", Product: "chrome", Range: VersionRange{EndIncluding: "31.0.1650.62"}},
		{Part: "a", Vendor: "google", Product: "chrome", Range: VersionRange{Exact: "31.0.1650.0"}},
	}
	if !slices.Equal(recs[0].Matches, want) {
		t.Errorf("eşleşmeler = %+v", recs[0].Matches)
	}
	for _, m := range recs[0].Matches {
		if m.Range.Contains("130.0.6723.92") {
			t.Errorf("güncel Chrome eski açığa eşleşmemeli: %+v", m)
		}
	}
}

func TestParseCPE(t *testing.T) {
	if pm, ok := parseCPE(`cpe:2.3:a:notepad-plus-plus:notepad\+\+:8.6:*:*:*:*:*:*:*`); !ok ||
		pm.Product != `notepad\+\+` || pm.Range.Exact != "8.6" {
		t.Errorf("kaçışlı CPE = %+v %v", pm, ok)
	}
	if _, ok := parseCPE("cpe:2.3:o:apple:macos:10.15.7:security_update_2021-001:*:*:*:*:*:*"); ok {
		t.Error("güncelleme alanlı tam sürüm atlanmalı")
	}
	if _, ok := parseCPE("cpe:2.3:h:intel:cpu:*:*:*:*:*:*:*:*"); ok {
		t.Error("donanım CPE'leri atlanmalı")
	}
}

func TestParseKEVAndEPSS(t *testing.T) {
	f, _ := os.Open("testdata/kev.json")
	defer f.Close()
	kev, err := ParseKEV(f)
	if err != nil || len(kev) != 3 || kev[0].CVE != "CVE-2026-118527" || kev[0].DueDate == nil {
		t.Fatalf("KEV = %+v, %v", kev, err)
	}

	e, _ := os.Open("testdata/epss.csv")
	defer e.Close()
	var got []EPSSScore
	day, n, err := ParseEPSS(e, func(s EPSSScore) error { got = append(got, s); return nil })
	if err != nil || n != 5 || day.Format("2006-01-02") != "2026-10-30" {
		t.Fatalf("EPSS: n=%d gün=%v hata=%v", n, day, err)
	}
	if got[1].CVE != "CVE-1999-0002" || got[1].Score != 0.27183 || got[1].Percentile != 0.98051 {
		t.Errorf("EPSS satırı = %+v", got[1])
	}
}

func TestParseMSRC(t *testing.T) {
	f, _ := os.Open("testdata/msrc.json")
	defer f.Close()
	recs, err := ParseMSRC(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("Azure Linux kaydı atlanmalı, %d kayıt", len(recs))
	}
	r := recs[0]
	if r.ID != "CVE-2026-100200" || r.Title == "" || r.CVSS == nil || r.Severity == "" {
		t.Errorf("kayıt = %+v", r)
	}
	want := Remediation{KB: "KB5126653", BuildFamily: "10.0.22631", FixedBuild: "10.0.22631.7652", Severity: "Important"}
	if !slices.Contains(r.Remediations, want) {
		t.Errorf("düzeltmeler = %+v", r.Remediations)
	}
}

type fakeLookup struct {
	builds   map[string][]BuildFix
	kbs      map[string][]string
	products map[string][]CPEMatch
}

func (f fakeLookup) BuildFixes(_ context.Context, fam string) ([]BuildFix, error) {
	return f.builds[fam], nil
}

func (f fakeLookup) KBCVEs(_ context.Context, kbs []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, kb := range kbs {
		if v, ok := f.kbs[kb]; ok {
			out[kb] = v
		}
	}
	return out, nil
}

func (f fakeLookup) ProductMatches(_ context.Context, key string) ([]CPEMatch, error) {
	return f.products[key], nil
}

func TestCorrelate(t *testing.T) {
	m, _ := NewMatcher(nil)
	lk := NewCachedLookup(fakeLookup{
		builds: map[string][]BuildFix{"10.0.22631": {
			{CVE: "CVE-2026-0001", KB: "KB5126653", FixedBuild: "10.0.22631.7652"},
			{CVE: "CVE-2025-0002", KB: "KB5000001", FixedBuild: "10.0.22631.4000"},
		}},
		kbs: map[string][]string{"KB5040000": {"CVE-2026-0003"}},
		products: map[string][]CPEMatch{
			"a:7-zip:7-zip": {
				{CVE: "CVE-2026-0004", Range: VersionRange{EndExcluding: "26.01"}},
				{CVE: "CVE-2011-3389"}, // sürüm sınırı yok: atlanmalı
			},
			"a:google:chrome": {{CVE: "CVE-2026-0005", Range: VersionRange{EndExcluding: "100.0"}}},
		},
	})
	in := MachineInput{
		Platform: "windows",
		OSBuild:  "10.0.22631.4460",
		Missing: []MissingRef{
			{KB: "KB5040000", CVEs: []string{"cve-2026-0006", "geçersiz"}},
		},
		Apps: []AppRef{
			{Name: "7-Zip 24.08 (x64)", Version: "24.08"},
			{Name: "Google Chrome", Version: "130.0.1"},
			{Name: "org.mozilla.firefox", Version: "1", Source: "pkg"}, // makbuz: atlanmalı
			{Name: "7-Zip", Version: "1.0", Source: "pkg"},
		},
	}
	got, err := Correlate(context.Background(), in, m, lk)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(got))
	for i, f := range got {
		ids[i] = f.CVE
	}
	want := []string{"CVE-2026-0001", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0006"}
	if !slices.Equal(ids, want) {
		t.Fatalf("bulgular = %v, beklenen %v", ids, want)
	}
	if got[0].Sources[0] != SourceOSBuild || !slices.Contains(got[0].FixedBy, "KB5126653") ||
		!slices.Contains(got[0].FixedBy, "10.0.22631.7652") {
		t.Errorf("yapı bulgusu = %+v", got[0])
	}
	if got[2].Sources[0] != SourceApp || got[2].Refs[0] != "7-Zip 24.08 (x64) 24.08" || got[2].FixedBy[0] != ">= 26.01" {
		t.Errorf("uygulama bulgusu = %+v", got[2])
	}

	mac := MachineInput{Platform: "darwin", OSVersion: "15.1"}
	lk2 := fakeLookup{products: map[string][]CPEMatch{"o:apple:macos": {
		{CVE: "CVE-2026-0010", Range: VersionRange{StartIncluding: "15.0", EndExcluding: "15.2"}},
		{CVE: "CVE-2026-0011", Range: VersionRange{EndExcluding: "14.7"}},
	}}}
	got, _ = Correlate(context.Background(), mac, m, lk2)
	if len(got) != 1 || got[0].CVE != "CVE-2026-0010" || got[0].Sources[0] != SourceOS {
		t.Errorf("macOS bulguları = %+v", got)
	}
}

func TestNormalizeKBAndFamily(t *testing.T) {
	if NormalizeKB("5034441") != "KB5034441" || NormalizeKB("kb5034441") != "KB5034441" || NormalizeKB("abc") != "" {
		t.Error("NormalizeKB hatalı")
	}
	if BuildFamily("10.0.22631.4460") != "10.0.22631" || BuildFamily("24B83") != "" {
		t.Error("BuildFamily hatalı")
	}
}
