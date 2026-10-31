package api

import (
	"crypto/ed25519"
	"encoding/json"
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
