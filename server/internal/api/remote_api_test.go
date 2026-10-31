package api

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func TestRemoteManagement(t *testing.T) {
	oldPoll, oldCall := remotePollWait, remoteCallWait
	remotePollWait, remoteCallWait = 2*time.Second, 3*time.Second
	t.Cleanup(func() { remotePollWait, remoteCallWait = oldPoll, oldCall })

	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	secret := e.adminCreateKey(map[string]any{"name": "uzak"})
	_, ag := e.enroll(secret, "PC-UZAK")
	client := e.agentClient(ag.tlsCert(t))
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")
	base := "/api/v1/machines/" + ag.id + "/remote"
	perf := map[string]any{"op": "performance"}

	// Varsayılan kapalı: oturum açılamaz, heartbeat bayrak taşımaz.
	resp, out := admin.do("POST", base+"/session", nil, true)
	if resp.StatusCode != 409 || out["code"] != "remote.disabled" {
		t.Fatalf("kapalıyken oturum: %d %v", resp.StatusCode, out)
	}
	if hr := e.heartbeat(client, nil); hr.Remote != nil || hr.RemoteUntil != nil {
		t.Errorf("kapalıyken bayrak gönderilmemeli: %+v", hr)
	}
	resp, _ = ro.do("PUT", "/api/v1/settings/remote", map[string]any{"enabled": true, "session_minutes": 10}, true)
	expectStatus(t, resp, 403, "salt okunur ana anahtar")
	resp, _ = admin.do("PUT", "/api/v1/settings/remote", map[string]any{"enabled": true, "session_minutes": 10}, true)
	expectStatus(t, resp, 200, "ana anahtar")
	resp, _ = admin.do("PUT", base+"/settings", map[string]any{"performance": true, "services": true, "registry_read": true}, true)
	expectStatus(t, resp, 200, "makine bayrakları (Windows)")

	resp, _ = admin.do("POST", base+"/call", perf, true)
	expectStatus(t, resp, 409, "oturumsuz çağrı")
	resp, _ = ro.do("POST", base+"/session", nil, true)
	expectStatus(t, resp, 403, "salt okunur oturum açamaz")
	resp, out = admin.do("POST", base+"/session", nil, true)
	expectStatus(t, resp, 200, "oturum")
	if out["active"] != true || out["connected"] != false {
		t.Errorf("oturum durumu = %v", out)
	}
	e.clock = time.Now() // imzalı isteğin süresi gerçek saatle doğrulanır
	hr := e.heartbeat(client, nil)
	if hr.Remote == nil || !hr.Remote.Performance || hr.Remote.RegistryWrite || hr.RemoteUntil == nil {
		t.Fatalf("heartbeat oturumu bildirmeli: %+v", hr)
	}
	pub := ed25519.PublicKey(hr.ActionKey)

	// Ajan uzun yoklama yapar, isteği doğrular ve sonucu gönderir.
	agentDone := make(chan error, 1)
	go func() {
		r, body := e.agentGet(client, protocol.PathRemotePoll, nil)
		if r.StatusCode != 200 {
			agentDone <- fmt.Errorf("yoklama %d", r.StatusCode)
			return
		}
		var sj protocol.SignedJob
		_ = json.Unmarshal(body, &sj)
		req, err := sj.VerifyRemote(pub, ag.id, time.Now())
		if err != nil || req.Op != protocol.RemotePerformance {
			agentDone <- fmt.Errorf("doğrulama: %v %+v", err, req)
			return
		}
		data, _ := json.Marshal(protocol.PerfSnapshot{CPUPercent: 12.5, CPUCores: 8})
		rr, _ := e.postAgent(client, fmt.Sprintf(protocol.PathRemoteResultFmt, req.ID), protocol.RemoteResult{OK: true, Data: data})
		if rr.StatusCode != 204 {
			agentDone <- fmt.Errorf("sonuç %d", rr.StatusCode)
			return
		}
		agentDone <- nil
	}()
	time.Sleep(200 * time.Millisecond)
	resp, out = admin.do("POST", base+"/call", perf, true)
	expectStatus(t, resp, 200, "performans çağrısı")
	if out["cpu_percent"].(float64) != 12.5 {
		t.Errorf("performans = %v", out)
	}
	if err := <-agentDone; err != nil {
		t.Fatal(err)
	}
	resp, out = admin.do("GET", base, nil, false)
	expectStatus(t, resp, 200, "durum")
	if out["connected"] != true {
		t.Errorf("yoklamadan sonra bağlı görünmeli: %v", out)
	}

	// Kapalı özellik ve geçersiz parametre ajana gitmeden reddedilir.
	resp, out = admin.do("POST", base+"/call", map[string]any{"op": "registry.set",
		"params": map[string]any{"path": `HKLM\SOFTWARE\X`, "value": map[string]string{"name": "a", "type": "REG_SZ", "data": "b"}}}, true)
	if resp.StatusCode != 409 {
		t.Errorf("kayıt defteri yazma kapalı: %d %v", resp.StatusCode, out)
	}
	resp, _ = admin.do("POST", base+"/call", map[string]any{"op": "registry.list", "params": map[string]string{"path": `HKXX\Yok`}}, true)
	expectStatus(t, resp, 400, "geçersiz yol")
	resp, _ = ro.do("POST", base+"/call", perf, true)
	expectStatus(t, resp, 403, "salt okunur çağrı")

	// Ajan yanıt vermezse zaman aşımı; hata sonucu denetim kaydına yazılır.
	resp, out = admin.do("POST", base+"/call", map[string]any{"op": "services.control",
		"params": map[string]string{"name": "Spooler", "action": "restart"}}, true)
	if resp.StatusCode != http.StatusGatewayTimeout || out["code"] != "remote.timeout" {
		t.Errorf("zaman aşımı: %d %v", resp.StatusCode, out)
	}
	resp, out = admin.do("GET", "/api/v1/audit?action=remote.", nil, false)
	expectStatus(t, resp, 200, "denetim")
	actions := map[string]bool{}
	for _, it := range out["items"].([]any) {
		actions[it.(map[string]any)["action"].(string)] = true
	}
	if !actions["remote.session"] || !actions["remote.services.control"] {
		t.Errorf("uzaktan işlemler denetim kaydında olmalı: %v", actions)
	}
}
