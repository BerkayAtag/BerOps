package api

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// offlineFeeds, cve paketinin gerçek kaynaklardan kesilmiş test dosyalarıyla çevrimdışı bir
// kaynak klasörü hazırlar. KEV ve EPSS dosyaları test edilen 7-Zip açığını içerecek şekilde yazılır.
func offlineFeeds(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("..", "cve", "testdata")
	copyFile := func(from, to string) {
		b, err := os.ReadFile(filepath.Join(src, from))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, to)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, to), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	copyFile("nvd_7zip.json", "nvd/nvd_7zip.json")
	copyFile("msrc.json", "msrc/2026-Oct.json")
	kev := `{"vulnerabilities":[{"cveID":"CVE-2026-48112","vendorProject":"7-Zip","product":"7-Zip",
		"vulnerabilityName":"7-Zip test açığı","dateAdded":"2026-10-01","dueDate":"2026-10-22",
		"requiredAction":"Güncelleyin","knownRansomwareCampaignUse":"Known"}]}`
	epss := "#model_version:v1,score_date:2026-10-30T00:00:00Z\ncve,epss,percentile\nCVE-2026-48112,0.90000,0.99000\n"
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), []byte(kev), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "epss.csv"), []byte(epss), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func (b *browser) raw(path string) (*http.Response, []byte) {
	b.e.t.Helper()
	resp, err := b.c.Get(b.e.console.URL + path)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, body
}

func findItem(items []any, key, val string) map[string]any {
	for _, it := range items {
		m := it.(map[string]any)
		if m[key] == val {
			return m
		}
	}
	return nil
}

func TestCVEPipelineAndReports(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("tekniker", "technician")
	e.createUser("izleyici", "readonly")
	e.srv.cfg.CVE.OfflineDir = offlineFeeds(t)
	e.srv.cveSync = e.srv.newSyncer()

	secret := e.adminCreateKey(map[string]any{"name": "cve"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	rep := sampleReport(e.clock)
	rep.Apps = append(rep.Apps, protocol.App{Name: "7-Zip 24.08 (x64)", Version: "24.08", Source: protocol.AppSourceRegistry})
	rep.Hashes["apps"] = protocol.HashSection(rep.Apps)
	rep.MissingPatches = append(rep.MissingPatches, protocol.MissingPatch{ID: "u2", KB: "KB5126653",
		Title: "2026-10 Toplu Güncelleştirme", Classification: "Security Updates", Severity: "Important"})
	expectStatus(t, e.postInventory(client, rep, true), 204, "envanter")

	ctx := context.Background()
	if err := e.srv.cveSync.Sync(ctx); err != nil {
		t.Fatalf("çevrimdışı eşitleme: %v", err)
	}
	e.srv.vulns.RecomputeAll()
	if err := e.srv.vulns.Flush(ctx); err != nil {
		t.Fatal(err)
	}

	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")

	resp, out := ro.do("GET", "/api/v1/machines/"+ag.id+"/vulnerabilities", nil, false)
	expectStatus(t, resp, 200, "makine zafiyetleri")
	items := out["items"].([]any)
	// 7-Zip: 3 NVD açığı; Windows yapısı 4460 < 7652: 2 MSRC açığı; WUA'nın bildirdiği 1 CVE.
	if len(items) != 6 {
		t.Fatalf("6 bulgu beklenirdi, %d: %v", len(items), items)
	}
	top := items[0].(map[string]any)
	if top["cve_id"] != "CVE-2026-48112" || top["kev"] != true || top["risk_score"].(float64) < 80 || top["title"] == "" {
		t.Errorf("en riskli bulgu KEV'deki 7-Zip açığı olmalı: %v", top)
	}
	win := findItem(items, "cve_id", "CVE-2026-100200")
	if win == nil || !strings.Contains(strings.Join(toStrings(win["sources"]), ","), "os_build") ||
		!strings.Contains(strings.Join(toStrings(win["fixed_by"]), ","), "KB5126653") {
		t.Errorf("MSRC yapı bulgusu = %v", win)
	}
	if wua := findItem(items, "cve_id", "CVE-2024-43451"); wua == nil || wua["sources"].([]any)[0] != "missing_patch" {
		t.Errorf("WUA CVE bulgusu = %v", wua)
	}

	resp, out = ro.do("GET", "/api/v1/vulnerabilities?kev=true", nil, false)
	expectStatus(t, resp, 200, "zafiyet listesi")
	if out["total"].(float64) != 1 {
		t.Errorf("KEV filtresi 1 sonuç vermeli: %v", out)
	}
	resp, out = ro.do("GET", "/api/v1/vulnerabilities?sort=cve&desc=false&kind=app", nil, false)
	expectStatus(t, resp, 200, "uygulama zafiyetleri")
	if out["total"].(float64) != 3 || out["items"].([]any)[0].(map[string]any)["cve_id"] != "CVE-2026-14266" {
		t.Errorf("uygulama filtresi/sıralama = %v", out)
	}
	resp, _ = ro.do("GET", "/api/v1/vulnerabilities?severity=bilinmez", nil, false)
	expectStatus(t, resp, 400, "geçersiz önem")

	resp, out = ro.do("GET", "/api/v1/vulnerabilities/cve-2026-48112", nil, false)
	expectStatus(t, resp, 200, "CVE detayı")
	if out["kev"] == nil || len(out["affected"].([]any)) != 1 || out["description"] == "" {
		t.Errorf("CVE detayı = %v", out)
	}
	resp, _ = ro.do("GET", "/api/v1/vulnerabilities/CVE-1999-99999", nil, false)
	expectStatus(t, resp, 404, "bilinmeyen CVE")

	resp, out = ro.do("GET", "/api/v1/dashboard/risk", nil, false)
	expectStatus(t, resp, 200, "risk özeti")
	if out["kev_machines"].(float64) != 1 || out["distinct_cves"].(float64) != 6 || len(out["top_machines"].([]any)) != 1 {
		t.Errorf("risk özeti = %v", out)
	}

	resp, out = ro.do("GET", "/api/v1/machines?sort=risk&desc=true", nil, false)
	expectStatus(t, resp, 200, "makine listesi")
	if m := out["items"].([]any)[0].(map[string]any); m["vuln_count"].(float64) != 6 || m["kev_count"].(float64) != 1 {
		t.Errorf("makine listesi risk sütunları = %v", m)
	}

	// Kaynak durumu ve eşitleme yetkisi.
	resp, out = ro.do("GET", "/api/v1/cve/status", nil, false)
	expectStatus(t, resp, 200, "CVE durumu")
	for _, f := range out["feeds"].([]any) {
		if fm := f.(map[string]any); fm["last_success_at"] == nil || fm["last_error"] != "" {
			t.Errorf("kaynak eşitlenmemiş: %v", fm)
		}
	}
	resp, _ = ro.do("POST", "/api/v1/cve/sync", nil, true)
	expectStatus(t, resp, 403, "salt okunur eşitleme")

	// Raporlar: tüm roller dışa aktarabilir.
	resp, body := ro.raw("/api/v1/reports/vulnerabilities?format=csv&lang=en")
	expectStatus(t, resp, 200, "CSV rapor")
	if !strings.Contains(string(body), "CVE-2026-48112") || !strings.HasPrefix(resp.Header.Get("Content-Disposition"), `attachment; filename="vulnerability-report-`) {
		t.Errorf("CSV raporu hatalı: %s", body)
	}
	resp, body = ro.raw("/api/v1/reports/compliance?format=xlsx&tz=Europe/Istanbul")
	expectStatus(t, resp, 200, "Excel rapor")
	if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
		t.Errorf("Excel dosyası açılamadı: %v", err)
	}
	for _, kind := range []string{"compliance", "vulnerabilities", "missing-patches", "apps"} {
		resp, body = ro.raw("/api/v1/reports/" + kind + "?format=pdf")
		expectStatus(t, resp, 200, kind+" PDF")
		if !bytes.HasPrefix(body, []byte("%PDF-")) {
			t.Errorf("%s PDF değil", kind)
		}
	}
	resp, _ = ro.raw("/api/v1/reports/yok?format=pdf")
	expectStatus(t, resp, 404, "bilinmeyen rapor")
	resp, _ = ro.raw("/api/v1/reports/apps?format=docx")
	expectStatus(t, resp, 400, "bilinmeyen biçim")

	// Özel kurallar yalnızca ayar yazma yetkisiyle.
	tech := e.browser()
	expectStatus(t, tech.login("tekniker", testPassword), 200, "giriş")
	rule := map[string]string{"name": "^ozel uygulama$", "vendor": "ornek", "product": "ozel_uygulama"}
	resp, _ = tech.do("POST", "/api/v1/cve/rules", rule, true)
	expectStatus(t, resp, 403, "teknisyen kural ekleme")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	resp, _ = admin.do("POST", "/api/v1/cve/rules", map[string]string{"name": "(", "vendor": "a", "product": "b"}, true)
	expectStatus(t, resp, 400, "geçersiz kural")
	resp, created := admin.do("POST", "/api/v1/cve/rules", rule, true)
	expectStatus(t, resp, 201, "kural ekleme")
	resp, out = admin.do("GET", "/api/v1/cve/rules", nil, false)
	expectStatus(t, resp, 200, "kurallar")
	if first := out["items"].([]any)[0].(map[string]any); first["product"] != "ozel_uygulama" || first["builtin"] != false {
		t.Errorf("özel kural listenin başında olmalı: %v", first)
	}
	resp, _ = admin.do("DELETE", "/api/v1/cve/rules/"+created["id"].(string), nil, true)
	expectStatus(t, resp, 204, "kural silme")
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
