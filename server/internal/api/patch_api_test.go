package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestPatchJobValidation(t *testing.T) {
	shell, cmd, codes, err := patchJob(protocol.PlatformWindows, []string{"3B0A6F2C-1D4E-4F5A-9B8C-7D6E5F4A3B2C"})
	if err != nil || shell != protocol.ShellPowerShell || !strings.Contains(cmd, "'3B0A6F2C-1D4E-4F5A-9B8C-7D6E5F4A3B2C'") ||
		len(codes) != 2 || codes[1] != 3010 {
		t.Fatalf("windows: %v %s %v", err, shell, codes)
	}
	shell, cmd, _, err = patchJob(protocol.PlatformDarwin, []string{"Safari18.1-18.1", "macOS Sequoia 15.1.1-24B91"})
	if err != nil || shell != protocol.ShellSh || !strings.Contains(cmd, "'macOS Sequoia 15.1.1-24B91'") {
		t.Fatalf("macos: %v %s", err, cmd)
	}
	for _, bad := range [][]string{nil, {"u1"}, {"3B0A6F2C-1D4E-4F5A-9B8C-7D6E5F4A3B2C'; Remove-Item C:\\"}} {
		if _, _, _, err := patchJob(protocol.PlatformWindows, bad); err == nil {
			t.Errorf("geçersiz windows kimliği kabul edildi: %q", bad)
		}
	}
	for _, bad := range []string{"x'; rm -rf /", "a$(id)", "-rf"} {
		if _, _, _, err := patchJob(protocol.PlatformDarwin, []string{bad}); err == nil {
			t.Errorf("geçersiz macOS etiketi kabul edildi: %q", bad)
		}
	}
}

func TestPatchDeployment(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("tekniker", "technician")
	secret := e.adminCreateKey(map[string]any{"name": "yama"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	const updateID = "3B0A6F2C-1D4E-4F5A-9B8C-7D6E5F4A3B2C"
	rep := sampleReport(e.clock)
	rep.MissingPatches = []protocol.MissingPatch{{ID: updateID, KB: "KB5046617", Title: "2024-11 Toplu Güncelleştirme",
		Classification: "Security Updates", Severity: "Critical", RebootRequired: true, CVEs: []string{"CVE-2024-43451"}}}
	rep.Hashes["missing_patches"] = protocol.HashSection(rep.MissingPatches)
	expectStatus(t, e.postInventory(client, rep, false), 204, "envanter")
	hr := e.heartbeat(client, nil)

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	tech := e.browser()
	expectStatus(t, tech.login("tekniker", testPassword), 200, "giriş")

	resp, out := tech.do("GET", "/api/v1/patches?platform=windows", nil, false)
	expectStatus(t, resp, 200, "yama listesi")
	items := out["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["kb"] != "KB5046617" || items[0].(map[string]any)["machines"].(float64) != 1 {
		t.Fatalf("yama listesi = %v", items)
	}
	resp, out = tech.do("GET", "/api/v1/patches/machines?update_id="+updateID, nil, false)
	expectStatus(t, resp, 200, "yama makineleri")
	if ms := out["items"].([]any); len(ms) != 1 || ms[0].(map[string]any)["id"] != ag.id {
		t.Fatalf("makineler = %v", ms)
	}

	body := map[string]any{"kind": "deploy_patch", "patches": []string{updateID}, "machine_ids": []string{ag.id}}
	resp, _ = tech.do("POST", "/api/v1/actions", body, true)
	expectStatus(t, resp, 403, "teknisyen yama dağıtamaz")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "deploy_patch", "patches": []string{"KB5046617'"},
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 400, "geçersiz kimlik")
	resp, act := admin.do("POST", "/api/v1/actions", body, true)
	expectStatus(t, resp, 201, "yama dağıtımı")
	if act["status"] != "active" || act["kind"] != "deploy_patch" || !strings.Contains(act["name"].(string), "1 güncelleme") {
		t.Fatalf("aksiyon = %v", act)
	}

	r, raw := e.agentGet(client, protocol.PathJobs, nil)
	expectStatus(t, r, 200, "işler")
	var jr protocol.JobsResponse
	_ = json.Unmarshal(raw, &jr)
	if len(jr.Jobs) != 1 {
		t.Fatalf("1 iş beklenirdi: %s", raw)
	}
	job, err := jr.Jobs[0].Verify(ed25519.PublicKey(hr.ActionKey), ag.id, time.Now())
	if err != nil || job.Kind != protocol.JobDeployPatch || !job.RescanAfter || job.TimeoutSeconds != 7200 ||
		!strings.Contains(job.Command, "Microsoft.Update.Session") || len(job.Patches) != 1 {
		t.Fatalf("iş = %v %+v", err, job)
	}
}

func TestRestartLogsAndSchedule(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("tekniker", "technician")
	secret := e.adminCreateKey(map[string]any{"name": "zamanlama"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	hr := e.heartbeat(client, nil)
	pub := ed25519.PublicKey(hr.ActionKey)
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	tech := e.browser()
	expectStatus(t, tech.login("tekniker", testPassword), 200, "giriş")
	ids := []string{ag.id}

	resp, _ := tech.do("POST", "/api/v1/actions", map[string]any{"kind": "restart", "machine_ids": ids}, true)
	expectStatus(t, resp, 403, "teknisyen yeniden başlatamaz")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "restart", "machine_ids": ids,
		"restart_message": "kaydet' ; Remove-Item C:\\"}, true)
	expectStatus(t, resp, 400, "tırnaklı ileti")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "restart", "machine_ids": ids, "restart_delay_minutes": 2000}, true)
	expectStatus(t, resp, 400, "uzun süre")

	// Zamanlanmış yeniden başlatma: başlangıç zamanından önce ajana verilmez.
	start := e.clock.Add(2 * time.Hour).UTC().Format(time.RFC3339)
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "restart", "machine_ids": ids,
		"restart_delay_minutes": 15, "restart_message": "Bakım için yeniden başlatılacak, işinizi kaydedin.", "not_before": start}, true)
	expectStatus(t, resp, 201, "zamanlanmış yeniden başlatma")
	if act["not_before"] == nil || !strings.Contains(act["name"].(string), "15 dk") {
		t.Fatalf("aksiyon = %v", act)
	}
	if n := e.jobCount(client); n != 0 {
		t.Fatalf("başlangıçtan önce iş verilmemeli: %d", n)
	}
	e.clock = e.clock.Add(3 * time.Hour)
	r, raw := e.agentGet(client, protocol.PathJobs, nil)
	expectStatus(t, r, 200, "işler")
	var jr protocol.JobsResponse
	_ = json.Unmarshal(raw, &jr)
	if len(jr.Jobs) != 1 {
		t.Fatalf("başlangıç geçince iş verilmeli: %s", raw)
	}
	job, err := jr.Jobs[0].Verify(pub, ag.id, e.clock)
	if err != nil || job.Kind != protocol.JobRestart || !strings.Contains(job.Command, "shutdown.exe /r /t 900") {
		t.Fatalf("yeniden başlatma işi = %v %+v", err, job)
	}

	// Günlük isteği komut taşımaz; ajan imzayı doğrulayabilir.
	expectStatus(t, admin.login("admin", testPassword), 200, "yeniden giriş")
	expectStatus(t, tech.login("tekniker", testPassword), 200, "yeniden giriş")
	resp, _ = tech.do("POST", "/api/v1/actions", map[string]any{"kind": "collect_logs", "machine_ids": ids}, true)
	expectStatus(t, resp, 403, "teknisyen günlük isteyemez")
	resp, act = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "collect_logs", "machine_ids": ids}, true)
	expectStatus(t, resp, 201, "günlük isteği")
	_, raw = e.agentGet(client, protocol.PathJobs, nil)
	_ = json.Unmarshal(raw, &jr)
	found := false
	for _, sj := range jr.Jobs {
		j, err := sj.Verify(pub, ag.id, e.clock)
		if err == nil && j.Kind == protocol.JobCollectLogs && j.Command == "" && j.ID == act["id"] {
			found = true
		}
	}
	if !found {
		t.Fatalf("günlük işi bulunamadı: %s", raw)
	}
	zero := 3010
	rr, _ := e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, act["id"]), protocol.JobStatusRequest{Status: "succeeded", ExitCode: &zero, Stdout: "satır"})
	expectStatus(t, rr, 204, "sonuç")
	resp, out := admin.do("GET", "/api/v1/actions/"+act["id"].(string), nil, false)
	expectStatus(t, resp, 200, "detay")
	tg := out["targets"].([]any)[0].(map[string]any)
	if tg["reboot_required"] != true || tg["stdout"] != "satır" {
		t.Errorf("3010 yeniden başlatma bekliyor olarak işaretlenmeli: %v", tg)
	}
}
