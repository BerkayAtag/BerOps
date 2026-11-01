package api

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestGroupsTagsAndTargeting(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")
	secret := e.adminCreateKey(map[string]any{"name": "grup"})

	// Üç Windows makinesi: Chrome 119, 130 ve Chrome'suz.
	var ids []string
	for i, ver := range []string{"119.0.6045.200", "130.0.6723.92", ""} {
		_, ag := e.enroll(secret, fmt.Sprintf("PC-%d", i))
		ids = append(ids, ag.id)
		rep := sampleReport(e.clock)
		rep.Apps = nil
		if ver != "" {
			rep.Apps = []protocol.App{{Name: "Google Chrome", Version: ver, Source: protocol.AppSourceMSI}}
		}
		rep.Hashes["apps"] = protocol.HashSection(rep.Apps)
		expectStatus(t, e.postInventory(e.agentClient(ag.tlsCert(t)), rep, false), 204, "envanter")
	}

	rule := map[string]any{"match": "all", "conditions": []map[string]any{
		{"field": "platform", "op": "eq", "value": "windows"},
		{"field": "app", "op": "version_lt", "name": "chrome", "value": "120"},
	}}
	resp, out := admin.do("POST", "/api/v1/groups/preview", rule, true)
	expectStatus(t, resp, 200, "önizleme")
	if out["total"].(float64) != 1 {
		t.Fatalf("Chrome < 120 tek makine olmalı: %v", out)
	}
	resp, _ = admin.do("POST", "/api/v1/groups/preview", map[string]any{"match": "all",
		"conditions": []map[string]any{{"field": "m.id; DROP TABLE machines", "op": "eq", "value": "x"}}}, true)
	expectStatus(t, resp, 400, "bilinmeyen alan")

	resp, _ = ro.do("POST", "/api/v1/groups", map[string]any{"name": "x", "kind": "static"}, true)
	expectStatus(t, resp, 403, "salt okunur grup oluşturamaz")
	resp, dyn := admin.do("POST", "/api/v1/groups", map[string]any{"name": "Eski Chrome", "kind": "dynamic", "rule": rule}, true)
	expectStatus(t, resp, 200, "dinamik grup")
	resp, _ = admin.do("POST", "/api/v1/groups", map[string]any{"name": "eski chrome", "kind": "static"}, true)
	expectStatus(t, resp, 409, "aynı ad")
	resp, st := admin.do("POST", "/api/v1/groups", map[string]any{"name": "Pilot", "kind": "static",
		"machine_ids": []string{ids[1], ids[2]}}, true)
	expectStatus(t, resp, 200, "statik grup")
	resp, _ = admin.do("PUT", "/api/v1/groups/"+st["id"].(string)+"/members", map[string]any{"remove": []string{ids[2]}}, true)
	expectStatus(t, resp, 204, "üye çıkar")

	resp, out = ro.do("GET", "/api/v1/groups", nil, false)
	expectStatus(t, resp, 200, "grup listesi")
	members := map[string]float64{}
	for _, g := range out["items"].([]any) {
		gm := g.(map[string]any)
		members[gm["name"].(string)] = gm["members"].(float64)
	}
	if members["Eski Chrome"] != 1 || members["Pilot"] != 1 {
		t.Fatalf("üye sayıları = %v", members)
	}

	resp, _ = admin.do("PUT", "/api/v1/machines/"+ids[0]+"/tags", map[string]any{"tags": []string{"sunucu", "İzmir"}}, true)
	expectStatus(t, resp, 200, "etiket")
	resp, _ = admin.do("PUT", "/api/v1/machines/"+ids[0]+"/tags", map[string]any{"tags": []string{"<script>"}}, true)
	expectStatus(t, resp, 400, "geçersiz etiket")
	resp, out = ro.do("GET", "/api/v1/machines?tag=izmir", nil, false)
	expectStatus(t, resp, 200, "etikete göre")
	if out["total"].(float64) != 1 {
		t.Errorf("etiket süzgeci = %v", out["total"])
	}
	resp, out = ro.do("GET", "/api/v1/machines?group_id="+dyn["id"].(string), nil, false)
	expectStatus(t, resp, 200, "gruba göre")
	if out["total"].(float64) != 1 {
		t.Errorf("grup süzgeci = %v", out["total"])
	}

	resp, _ = admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 10000, "max_upload_mb": 100,
		"command_approval": false, "default_expiry_hours": 24}, true)
	expectStatus(t, resp, 200, "aktarım")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"group_ids": []string{dyn["id"].(string), st["id"].(string)}}, true)
	expectStatus(t, resp, 201, "gruplara aksiyon")
	if act["target_count"].(float64) != 2 {
		t.Errorf("iki grubun birleşimi 2 makine olmalı: %v", act["target_count"])
	}
	resp, act = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"all_machines": true}, true)
	expectStatus(t, resp, 201, "tüm filo")
	if act["target_count"].(float64) != 3 {
		t.Errorf("tüm filo 3 makine olmalı: %v", act["target_count"])
	}
}

func TestRetryPolicy(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	secret := e.adminCreateKey(map[string]any{"name": "tekrar"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	hr := e.heartbeat(client, nil)
	resp, _ := admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 10000, "max_upload_mb": 100,
		"command_approval": false, "default_expiry_hours": 24}, true)
	expectStatus(t, resp, 200, "aktarım")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"machine_ids": []string{ag.id}, "retry_count": 9}, true)
	expectStatus(t, resp, 400, "en fazla 5 deneme")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"machine_ids": []string{ag.id}, "retry_count": 1, "retry_delay_minutes": 10}, true)
	expectStatus(t, resp, 201, "yeniden denemeli aksiyon")
	id := act["id"].(string)
	status := func(st string) {
		t.Helper()
		rr, _ := e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, id), protocol.JobStatusRequest{Status: st})
		expectStatus(t, rr, 204, st)
	}
	status("failed")
	if n := e.jobCount(client); n != 0 {
		t.Fatalf("bekleme süresinde iş verilmemeli: %d", n)
	}
	e.clock = e.clock.Add(11 * time.Minute)
	_, raw := e.agentGet(client, protocol.PathJobs, nil)
	var jr protocol.JobsResponse
	_ = json.Unmarshal(raw, &jr)
	if len(jr.Jobs) != 1 {
		t.Fatalf("bekleme sonrası iş yeniden verilmeli: %s", raw)
	}
	job, err := jr.Jobs[0].Verify(hr.ActionKey, ag.id, e.clock)
	if err != nil || job.Attempt != 1 {
		t.Fatalf("yeniden imzalanan iş = %v %+v", err, job)
	}
	status("failed") // deneme hakkı bitti: son durum
	expectStatus(t, admin.login("admin", testPassword), 200, "yeniden giriş")
	resp, out := admin.do("GET", "/api/v1/actions/"+id, nil, false)
	expectStatus(t, resp, 200, "detay")
	a := out["action"].(map[string]any)
	tg := out["targets"].([]any)[0].(map[string]any)
	if a["status"] != "completed" || tg["status"] != "failed" || tg["attempts"].(float64) != 1 {
		t.Errorf("deneme hakkı bitince aksiyon tamamlanmalı: %v / %v", a["status"], tg)
	}
}

func TestRateProfilesAndSharedLimiter(t *testing.T) {
	ist, _ := time.LoadLocation("Europe/Istanbul")
	set := store.TransferSettings{PerClientKbps: 10000, Profiles: []store.RateProfile{
		{Name: "Mesai", Weekdays: []int16{1, 2, 3, 4, 5}, StartMinute: 9 * 60, EndMinute: 18 * 60, Kbps: 2000},
		{Name: "Gece", Weekdays: []int16{5}, StartMinute: 22 * 60, EndMinute: 6 * 60, Kbps: 50000},
	}}
	cases := []struct {
		at   time.Time
		want int
	}{
		{time.Date(2026, 11, 2, 10, 0, 0, 0, ist), 2000},  // Pazartesi mesai
		{time.Date(2026, 11, 2, 19, 0, 0, 0, ist), 10000}, // Pazartesi akşam
		{time.Date(2026, 11, 6, 23, 0, 0, 0, ist), 50000}, // Cuma gece
		{time.Date(2026, 11, 7, 5, 59, 0, 0, ist), 50000}, // Cumartesi sabahı: Cuma gecesinin devamı
		{time.Date(2026, 11, 7, 6, 0, 0, 0, ist), 10000},
		{time.Date(2026, 11, 8, 10, 0, 0, 0, ist), 10000}, // Pazar
	}
	for _, c := range cases {
		if got := set.ClientKbps(c.at); got != c.want {
			t.Errorf("%s: %d beklenirdi, %d", c.at.Format(time.RFC1123), c.want, got)
		}
	}
	if validateProfiles([]store.RateProfile{{Name: "x", Weekdays: []int16{1}, StartMinute: 60, EndMinute: 60, Kbps: 100}}) == nil {
		t.Error("boş aralık kabul edilmemeli")
	}

	var l sharedLimiter
	if l.reserve(1<<20) != 0 {
		t.Error("sınırsız limiter beklememeli")
	}
	l.setKbps(8000) // 1 MB/sn
	if l.reserve(1_000_000) != 0 {
		t.Error("ilk parça hemen gitmeli")
	}
	if w := l.reserve(500_000); w < 900*time.Millisecond || w > 1100*time.Millisecond {
		t.Errorf("ikinci parça ~1 sn beklemeli (paylaşılan sınır): %s", w)
	}
}
