package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func (b *browser) upload(meta map[string]any, fileName string, content []byte) (*http.Response, map[string]any) {
	b.e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	mj, _ := json.Marshal(meta)
	_ = mw.WriteField("metadata", string(mj))
	fw, _ := mw.CreateFormFile("file", fileName)
	_, _ = fw.Write(content)
	_ = mw.Close()
	req, _ := http.NewRequest("POST", b.e.console.URL+"/api/v1/packages", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set(CSRFHeader, b.csrf)
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (e *env) agentGet(c *http.Client, path string, hdr map[string]string) (*http.Response, []byte) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.agent.URL+path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func TestPackagesActionsAndJobs(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("admin2", "admin")
	e.createUser("tekniker", "technician")
	e.createUser("izleyici", "readonly")
	secret := e.adminCreateKey(map[string]any{"name": "dagitim"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	hr := e.heartbeat(client, nil)
	pub := ed25519.PublicKey(hr.ActionKey)
	if len(pub) != ed25519.PublicKeySize || hr.PendingJobs != 0 {
		t.Fatalf("heartbeat aksiyon anahtarını taşımalı: %+v", hr)
	}
	// Envanterde eski 7-Zip var: paket "güncelleme gerekli" listesinde görünmeli.
	rep := sampleReport(e.clock)
	rep.Apps = append(rep.Apps, protocol.App{Name: "7-Zip 24.08 (x64)", Version: "24.08", Source: protocol.AppSourceRegistry})
	rep.Hashes["apps"] = protocol.HashSection(rep.Apps)
	expectStatus(t, e.postInventory(client, rep, false), 204, "envanter")

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	tech := e.browser()
	expectStatus(t, tech.login("tekniker", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")

	content := bytes.Repeat([]byte("BERPAKET"), 10_000) // 80 KB
	sum := sha256.Sum256(content)
	meta := map[string]any{"name": "7-Zip", "version": "26.01", "publisher": "Igor Pavlov", "platform": "windows",
		"installer": "msi", "detect_name": "^7-zip"}

	resp, _ := tech.upload(meta, "7z2601-x64.msi", content)
	expectStatus(t, resp, 403, "teknisyen paket yükleyemez")
	resp, out := admin.upload(map[string]any{"name": "x", "version": "1", "platform": "windows", "installer": "msi"}, "kur.exe", content)
	expectStatus(t, resp, 400, "uzantı uyuşmazlığı")
	resp, pkg := admin.upload(meta, `..\..\7z2601-x64.msi`, content)
	expectStatus(t, resp, 201, "paket yükleme")
	if pkg["file_sha256"] != hex.EncodeToString(sum[:]) || pkg["file_name"] != "7z2601-x64.msi" ||
		!strings.Contains(pkg["install_command"].(string), "msiexec") {
		t.Fatalf("paket = %v", pkg)
	}
	resp, _ = admin.upload(meta, "7z2601-x64.msi", content)
	expectStatus(t, resp, 409, "aynı sürüm")
	pkgID := pkg["id"].(string)

	resp, out = ro.do("GET", "/api/v1/packages/"+pkgID, nil, false)
	expectStatus(t, resp, 200, "paket detayı")
	if od := out["outdated"].([]any); len(od) != 1 || od[0].(map[string]any)["version"] != "24.08" {
		t.Errorf("güncelleme gereken makine listesi = %v", out["outdated"])
	}

	// Yetkiler: salt okunur hiçbir şey gönderemez; teknisyen yalnızca paket gönderebilir.
	deploy := map[string]any{"kind": "deploy_package", "package_id": pkgID, "machine_ids": []string{ag.id}}
	command := map[string]any{"kind": "run_command", "shell": "powershell", "command": "Get-Service", "machine_ids": []string{ag.id}}
	resp, _ = ro.do("POST", "/api/v1/actions", deploy, true)
	expectStatus(t, resp, 403, "salt okunur paket gönderemez")
	resp, _ = tech.do("POST", "/api/v1/actions", command, true)
	expectStatus(t, resp, 403, "teknisyen komut çalıştıramaz")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "zsh", "command": "ls",
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 400, "Windows'ta zsh")

	// Hız sınırı: 640 kbps = 80 KB/sn; 80 KB'lık dosya yaklaşık 1 saniyede iner.
	resp, _ = admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 640, "max_upload_mb": 100,
		"command_approval": true, "default_expiry_hours": 24}, true)
	expectStatus(t, resp, 200, "aktarım ayarı")
	resp, act := tech.do("POST", "/api/v1/actions", deploy, true)
	expectStatus(t, resp, 201, "teknisyen paket gönderir")
	actID := act["id"].(string)
	if act["status"] != "active" || act["bandwidth_kbps"].(float64) != 640 {
		t.Errorf("aksiyon = %v", act)
	}

	hr = e.heartbeat(client, nil)
	if hr.PendingJobs != 1 {
		t.Fatalf("bekleyen iş 1 olmalı: %d", hr.PendingJobs)
	}
	r, body := e.agentGet(client, protocol.PathJobs, nil)
	expectStatus(t, r, 200, "işler")
	var jr protocol.JobsResponse
	_ = json.Unmarshal(body, &jr)
	if len(jr.Jobs) != 1 {
		t.Fatalf("1 iş beklenirdi: %s", body)
	}
	job, err := jr.Jobs[0].Verify(pub, ag.id, time.Now())
	if err != nil || job.Package.SHA256 != pkg["file_sha256"] || !strings.Contains(job.Command, "{file}") {
		t.Fatalf("iş doğrulanamadı: %v %+v", err, job)
	}

	dl := fmt.Sprintf(protocol.PathPackageFileFmt, pkgID) + "?action=" + actID
	start := time.Now()
	r, got := e.agentGet(client, dl, nil)
	elapsed := time.Since(start)
	expectStatus(t, r, 200, "indirme")
	if !bytes.Equal(got, content) {
		t.Fatal("indirilen içerik farklı")
	}
	if elapsed < 700*time.Millisecond || r.Header.Get("X-Ber-Rate-Kbps") != "640" {
		t.Errorf("hız sınırı uygulanmadı: %s, %s kbps", elapsed, r.Header.Get("X-Ber-Rate-Kbps"))
	}
	r, got = e.agentGet(client, dl, map[string]string{"Range": "bytes=79990-"})
	if r.StatusCode != 206 || len(got) != 10 {
		t.Errorf("kaldığı yerden indirme: %d, %d bayt", r.StatusCode, len(got))
	}
	r, _ = e.agentGet(client, fmt.Sprintf(protocol.PathPackageFileFmt, pkgID)+"?action="+pkgID, nil)
	expectStatus(t, r, 404, "aksiyonsuz indirme")

	code := 3010
	rr, _ := e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, actID), protocol.JobStatusRequest{Status: "running"})
	expectStatus(t, rr, 204, "running")
	rr, _ = e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, actID),
		protocol.JobStatusRequest{Status: "succeeded", ExitCode: &code, Stdout: "kuruldu"})
	expectStatus(t, rr, 204, "succeeded")
	rr, _ = e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, actID), protocol.JobStatusRequest{Status: "failed"})
	expectStatus(t, rr, 409, "sonuçlanmış iş değişmez")

	resp, out = ro.do("GET", "/api/v1/actions/"+actID, nil, false)
	expectStatus(t, resp, 200, "aksiyon detayı")
	a := out["action"].(map[string]any)
	tg := out["targets"].([]any)[0].(map[string]any)
	if a["status"] != "completed" || tg["status"] != "succeeded" || tg["exit_code"].(float64) != 3010 || tg["stdout"] != "kuruldu" {
		t.Errorf("aksiyon sonucu = %v / %v", a, tg)
	}

	// Dört göz: komut onay bekler, oluşturan kişi onaylayamaz, başka admin onaylar.
	resp, act = admin.do("POST", "/api/v1/actions", command, true)
	expectStatus(t, resp, 201, "komut")
	cmdID := act["id"].(string)
	if act["status"] != "pending_approval" {
		t.Fatalf("komut onay beklemeli: %v", act["status"])
	}
	if hr = e.heartbeat(client, nil); hr.PendingJobs != 0 {
		t.Error("onaylanmamış iş ajana verilmemeli")
	}
	resp, _ = admin.do("POST", "/api/v1/actions/"+cmdID+"/approve", nil, true)
	expectStatus(t, resp, 403, "kendi aksiyonunu onaylayamaz")
	admin2 := e.browser()
	expectStatus(t, admin2.login("admin2", testPassword), 200, "giriş")
	resp, _ = admin2.do("POST", "/api/v1/actions/"+cmdID+"/approve", nil, true)
	expectStatus(t, resp, 200, "onay")
	if hr = e.heartbeat(client, nil); hr.PendingJobs != 1 {
		t.Errorf("onaydan sonra iş verilmeli: %d", hr.PendingJobs)
	}
	resp, _ = admin.do("POST", "/api/v1/actions/"+cmdID+"/cancel", nil, true)
	expectStatus(t, resp, 200, "iptal")
	if hr = e.heartbeat(client, nil); hr.PendingJobs != 0 {
		t.Error("iptal edilen iş verilmemeli")
	}
	rr, _ = e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, cmdID), protocol.JobStatusRequest{Status: "running"})
	expectStatus(t, rr, 409, "iptal edilen işe durum")

	resp, out = ro.do("GET", "/api/v1/actions?machine_id="+ag.id, nil, false)
	expectStatus(t, resp, 200, "aksiyon listesi")
	if out["total"].(float64) != 2 {
		t.Errorf("makinenin 2 aksiyonu olmalı: %v", out["total"])
	}

	// Denetim: aksiyon oluşturma kaydı komut metnini içerir.
	resp, out = admin.do("GET", "/api/v1/audit", nil, false)
	expectStatus(t, resp, 200, "denetim")
	found := false
	for _, it := range out["items"].([]any) {
		m := it.(map[string]any)
		if m["action"] == "action.create" && m["target_id"] == cmdID {
			found = m["params"].(map[string]any)["command"] == "Get-Service"
		}
	}
	if !found {
		t.Error("komut denetim kaydında olmalı")
	}

	// Paket silinince indirme de kapanır (açık aksiyon yok).
	resp, _ = tech.do("DELETE", "/api/v1/packages/"+pkgID, nil, true)
	expectStatus(t, resp, 403, "teknisyen paket silemez")
	resp, _ = admin.do("DELETE", "/api/v1/packages/"+pkgID, nil, true)
	expectStatus(t, resp, 204, "paket silme")
	resp, _ = ro.do("GET", "/api/v1/packages/"+pkgID, nil, false)
	expectStatus(t, resp, 404, "silinen paket")
}

func TestActionExpiry(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "sure"})
	_, ag := e.enroll(secret, "PC-002")
	client := e.agentClient(ag.tlsCert(t))
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"machine_ids": []string{ag.id}, "expires_hours": 1}, true)
	expectStatus(t, resp, 201, "komut")
	created := e.clock
	e.clock = e.clock.Add(2 * time.Hour)
	if hr := e.heartbeat(client, nil); hr.PendingJobs != 0 {
		t.Error("süresi dolan iş verilmemeli")
	}
	if _, err := e.store.ExpireActions(t.Context(), e.clock); err != nil {
		t.Fatal(err)
	}
	e.clock = created // oturum zamanları veritabanı saatiyle yazılır; konsol isteği için saat geri alınır
	resp, out := admin.do("GET", "/api/v1/actions/"+act["id"].(string), nil, false)
	expectStatus(t, resp, 200, "detay")
	if out["action"].(map[string]any)["status"] != "completed" || out["targets"].([]any)[0].(map[string]any)["status"] != "expired" {
		t.Errorf("süre dolumu = %v", out)
	}
}
