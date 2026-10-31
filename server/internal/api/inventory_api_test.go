package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func (e *env) postInventory(c *http.Client, rep protocol.InventoryReport, gz bool) *http.Response {
	e.t.Helper()
	buf, _ := json.Marshal(rep)
	var body bytes.Buffer
	if gz {
		zw := gzip.NewWriter(&body)
		_, _ = zw.Write(buf)
		_ = zw.Close()
	} else {
		body.Write(buf)
	}
	req, _ := http.NewRequest("POST", e.agent.URL+protocol.PathInventory, &body)
	req.Header.Set("Content-Type", "application/json")
	if gz {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	return resp
}

func (e *env) heartbeat(c *http.Client, hashes map[string]string) protocol.HeartbeatResponse {
	e.t.Helper()
	r, body := e.postAgent(c, protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-001"), InventoryHashes: hashes})
	expectStatus(e.t, r, 200, "heartbeat")
	var hr protocol.HeartbeatResponse
	_ = json.Unmarshal(body, &hr)
	return hr
}

func sampleReport(now time.Time) protocol.InventoryReport {
	apps := []protocol.App{{Name: "Google Chrome", Version: "130.0.6723.92", Source: protocol.AppSourceMSI}}
	missing := []protocol.MissingPatch{{ID: "u1", KB: "KB5046617", Title: "2024-11 Toplu Güncelleştirme",
		Classification: "Security Updates", Severity: "Critical", CVEs: []string{"CVE-2024-43451"}}}
	return protocol.InventoryReport{
		Full: true, CollectedAt: now, Included: protocol.AllSections,
		Hashes: map[string]string{
			"os": "h-os", "installed_patches": "h-ip", "missing_patches": "h-mp", "apps": protocol.HashSection(apps),
		},
		OS:               &protocol.OSInventory{Platform: "windows", Name: "Windows 11 Pro", Build: "10.0.22631.4460"},
		InstalledPatches: []protocol.InstalledPatch{{ID: "KB5044284", Source: "hotfix"}},
		MissingPatches:   missing,
		MissingScan:      &protocol.MissingScanInfo{Source: protocol.ScanSourceOnline, ScannedAt: now},
		Apps:             apps,
	}
}

func TestInventoryUploadAndHeartbeatInstructions(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	secret := e.adminCreateKey(map[string]any{"name": "envanter"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))

	// Ajan henüz envanter göndermediyse sunucu tam envanter istemez (ajan kendi takvimiyle tarar).
	hr := e.heartbeat(client, nil)
	if hr.RequestFullInventory || hr.Settings == nil || hr.Settings.ScanCPULimitPercent != 10 {
		t.Fatalf("ilk heartbeat: %+v", hr)
	}
	// Ajan özet bildirip sunucuda envanter yoksa tam envanter istenir.
	if hr := e.heartbeat(client, map[string]string{"apps": "x"}); !hr.RequestFullInventory {
		t.Error("sunucuda envanter yokken tam envanter istenmeli")
	}

	rep := sampleReport(e.clock)
	expectStatus(t, e.postInventory(client, rep, true), 204, "gzip envanter yükleme")

	if hr := e.heartbeat(client, rep.Hashes); hr.RequestFullInventory {
		t.Error("özetler eşleşince tam envanter istenmemeli")
	}
	if hr := e.heartbeat(client, map[string]string{"apps": "farkli"}); !hr.RequestFullInventory {
		t.Error("özet uyuşmazlığında tam envanter istenmeli")
	}

	// Sertifikasız envanter yüklenemez.
	r := e.postInventory(e.agentClient(nil), rep, false)
	expectStatus(t, r, 401, "sertifikasız envanter")

	// Geçersiz rapor reddedilir.
	bad := rep
	bad.Included = []string{"kayit_defteri"}
	expectStatus(t, e.postInventory(client, bad, false), 400, "bilinmeyen bölüm")

	// Konsol: liste, detay ve alt listeler.
	b := e.browser()
	expectStatus(t, b.login("izleyici", testPassword), 200, "giriş")
	resp, list := b.do("GET", "/api/v1/machines?platform=windows&sort=missing_count&desc=true&page_size=10", nil, false)
	expectStatus(t, resp, 200, "makine listesi")
	if list["total"].(float64) != 1 {
		t.Fatalf("liste: %v", list)
	}
	item := list["items"].([]any)[0].(map[string]any)
	if item["missing_count"].(float64) != 1 || item["missing_critical_count"].(float64) != 1 || item["app_count"].(float64) != 1 {
		t.Errorf("liste sayaçları: %v", item)
	}
	resp, _ = b.do("GET", "/api/v1/machines?platform=linux", nil, false)
	expectStatus(t, resp, 400, "geçersiz platform")

	resp, detail := b.do("GET", "/api/v1/machines/"+ag.id, nil, false)
	expectStatus(t, resp, 200, "makine detayı")
	inv := detail["inventory"].(map[string]any)
	if inv["os"].(map[string]any)["build"] != "10.0.22631.4460" || inv["missing_scan_source"] != "online" {
		t.Errorf("detay envanteri: %v", inv)
	}
	resp, mp := b.do("GET", "/api/v1/machines/"+ag.id+"/missing-patches", nil, false)
	expectStatus(t, resp, 200, "eksik yamalar")
	first := mp["items"].([]any)[0].(map[string]any)
	if first["kb"] != "KB5046617" || first["cves"].([]any)[0] != "CVE-2024-43451" {
		t.Errorf("eksik yama: %v", first)
	}
	resp, apps := b.do("GET", "/api/v1/machines/"+ag.id+"/apps", nil, false)
	expectStatus(t, resp, 200, "uygulamalar")
	if len(apps["items"].([]any)) != 1 {
		t.Errorf("uygulamalar: %v", apps)
	}
	resp, _ = b.do("GET", "/api/v1/machines/00000000-0000-4000-8000-000000000000", nil, false)
	expectStatus(t, resp, 404, "olmayan makine")
	resp, sum := b.do("GET", "/api/v1/machines/summary", nil, false)
	expectStatus(t, resp, 200, "filo özeti")
	if sum["total"].(float64) != 1 || sum["missing_total"].(float64) != 1 {
		t.Errorf("filo özeti: %v", sum)
	}

	// Salt okunur kullanıcı yeniden tarama isteyemez; admin isteyebilir ve ajan bunu heartbeat'te görür.
	resp, _ = b.do("POST", "/api/v1/machines/scan", map[string]any{"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 403, "salt okunur tarama isteği")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "admin girişi")
	e.clock = e.clock.Add(time.Minute)
	resp, _ = admin.do("POST", "/api/v1/machines/scan", map[string]any{"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 200, "admin tarama isteği")
	hr = e.heartbeat(client, rep.Hashes)
	if hr.ScanRequestedAt == nil {
		t.Fatal("tarama isteği heartbeat'te iletilmeli")
	}
	// Tam envanter geldikten sonra istek artık iletilmez.
	e.clock = e.clock.Add(time.Minute)
	expectStatus(t, e.postInventory(client, sampleReport(e.clock), false), 204, "tam envanter")
	if hr := e.heartbeat(client, rep.Hashes); hr.ScanRequestedAt != nil {
		t.Error("tam envanterden sonra tarama isteği temizlenmeli")
	}
}

func TestAgentSettingsAPI(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("teknisyen", "technician")
	e.createUser("izleyici", "readonly")

	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")
	resp, got := ro.do("GET", "/api/v1/settings/agent", nil, false)
	expectStatus(t, resp, 200, "salt okunur ayarları görebilir")
	if got["settings"].(map[string]any)["full_scan_interval_hours"].(float64) != 24 || got["wsus_cab"] != nil {
		t.Errorf("varsayılan ayarlar: %v", got)
	}

	newSet := protocol.DefaultAgentSettings()
	newSet.ScanCPULimitPercent = 5
	newSet.WindowsUpdateSource = protocol.ScanSourceOffline
	for _, u := range []string{"izleyici", "teknisyen"} {
		b := e.browser()
		expectStatus(t, b.login(u, testPassword), 200, u+" girişi")
		resp, _ := b.do("PUT", "/api/v1/settings/agent", newSet, true)
		expectStatus(t, resp, 403, u+" ayar değiştiremez")
	}

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "admin girişi")
	invalid := newSet
	invalid.ScanCPULimitPercent = 0
	resp, _ = admin.do("PUT", "/api/v1/settings/agent", invalid, true)
	expectStatus(t, resp, 400, "geçersiz ayar")
	resp, _ = admin.do("PUT", "/api/v1/settings/agent", newSet, true)
	expectStatus(t, resp, 200, "admin ayar değiştirebilir")

	// Önbellek geçersizleştirildiği için yeni ayar hemen ajana iletilir.
	secret := e.adminCreateKey(map[string]any{"name": "ayar"})
	_, ag := e.enroll(secret, "PC-001")
	hr := e.heartbeat(e.agentClient(ag.tlsCert(t)), nil)
	if hr.Settings.ScanCPULimitPercent != 5 || hr.Settings.WindowsUpdateSource != "offline" {
		t.Errorf("yeni ayar ajana iletilmeli: %+v", hr.Settings)
	}
}

func TestWSUSCabDownloadSupportsRange(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.srv.cfg.DataDir = t.TempDir()
	secret := e.adminCreateKey(map[string]any{"name": "cab"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))

	resp, err := client.Get(e.agent.URL + protocol.PathWSUSCab)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expectStatus(t, resp, 404, "katalog yokken")

	if err := os.MkdirAll(filepath.Dir(e.srv.wsusCabPath()), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.srv.wsusCabPath(), []byte("0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", e.agent.URL+protocol.PathWSUSCab, nil)
	req.Header.Set("Range", "bytes=4-")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	expectStatus(t, resp, 206, "kısmi indirme")
	if string(body) != "456789" {
		t.Errorf("kaldığı yerden devam eden indirme: %q", body)
	}

	resp, err = e.agentClient(nil).Get(e.agent.URL + protocol.PathWSUSCab)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expectStatus(t, resp, 401, "sertifikasız indirme")
}
