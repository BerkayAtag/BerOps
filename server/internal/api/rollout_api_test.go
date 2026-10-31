package api

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestWindowContains(t *testing.T) {
	ist, _ := time.LoadLocation("Europe/Istanbul")
	// Cumartesi 23:00'te başlayan 4 saatlik pencere (gece yarısını aşar).
	w := store.MaintenanceWindow{Weekdays: []int16{6}, StartMinute: 23 * 60, DurationMinutes: 240, Timezone: "Europe/Istanbul", Enabled: true}
	cases := []struct {
		at   time.Time
		want bool
	}{
		{time.Date(2026, 10, 31, 22, 59, 0, 0, ist), false}, // Cumartesi, başlamadan önce
		{time.Date(2026, 10, 31, 23, 30, 0, 0, ist), true},
		{time.Date(2026, 11, 1, 2, 59, 0, 0, ist), true}, // Pazar sabahı, pencere sürüyor
		{time.Date(2026, 11, 1, 3, 0, 0, 0, ist), false},
		{time.Date(2026, 11, 1, 23, 30, 0, 0, ist), false}, // Pazar akşamı pencere yok
		{time.Date(2026, 10, 31, 20, 30, 0, 0, time.UTC), true},
	}
	for _, c := range cases {
		if got := w.Contains(c.at); got != c.want {
			t.Errorf("%s: %v beklenirdi", c.at, c.want)
		}
	}
	inScope := func(ou string, scope []string) bool {
		return len(scope) == 0 || strings.HasSuffix(strings.ToLower(ou), strings.ToLower(scope[0]))
	}
	scoped := w
	scoped.ScopeOUs = []string{"OU=Sunucular,DC=ornek,DC=local"}
	closed := time.Date(2026, 10, 31, 12, 0, 0, 0, ist)
	if open, applies := store.OpenWindowsFor([]store.MaintenanceWindow{scoped}, "OU=Muhasebe,DC=ornek,DC=local", closed, inScope); !open || applies {
		t.Error("kapsam dışındaki makine için pencere uygulanmamalı")
	}
	if open, applies := store.OpenWindowsFor([]store.MaintenanceWindow{scoped}, "CN=SRV1,OU=Sunucular,DC=ornek,DC=local", closed, inScope); open || !applies {
		t.Error("kapsamdaki makine pencere dışında kapalı olmalı")
	}
}

func TestValidateAndAssignStages(t *testing.T) {
	bad := []store.Rollout{
		{Stages: []store.RolloutStage{{Percent: 100}}},
		{Stages: []store.RolloutStage{{Percent: 10}, {Percent: 80}}},
		{Stages: []store.RolloutStage{{Percent: 10}, {Percent: 90, DelayHours: 200}}},
		{Stages: []store.RolloutStage{{Percent: 10, DelayHours: 5}, {Percent: 40, DelayHours: 24}, {Percent: 50, DelayHours: 2}}},
	}
	for i := range bad {
		if validateRollout(&bad[i]) == nil {
			t.Errorf("geçersiz kademe kabul edildi: %+v", bad[i])
		}
	}
	r := &store.Rollout{Stages: []store.RolloutStage{{Percent: 10, DelayHours: 3}, {Percent: 40, DelayHours: 24}, {Percent: 50, DelayHours: 48}},
		MinSuccessPercent: 90}
	if err := validateRollout(r); err != nil || r.Stages[0].DelayHours != 0 {
		t.Fatalf("geçerli kademe: %v %+v", err, r)
	}
	ids := make([]string, 20)
	for i := range ids {
		ids[i] = fmt.Sprintf("m-%02d", i)
	}
	st := assignStages("aksiyon-1", ids, r)
	counts := map[int]int{}
	for _, s := range st {
		counts[s]++
	}
	if counts[0] != 2 || counts[1] != 8 || counts[2] != 10 {
		t.Errorf("aşama dağılımı = %v", counts)
	}
	if again := assignStages("aksiyon-1", ids, r); fmt.Sprint(again) != fmt.Sprint(st) {
		t.Error("aynı aksiyon için dağılım belirlenimli olmalı")
	}
	if few := assignStages("x", ids[:2], r); len(few) != 2 || few[ids[0]] == few[ids[1]] {
		t.Errorf("iki hedef farklı aşamalara düşmeli: %v", few)
	}
}

// jobCount, ajana verilen işlerin sayısını döner.
func (e *env) jobCount(c *http.Client) int {
	e.t.Helper()
	r, body := e.agentGet(c, protocol.PathJobs, nil)
	expectStatus(e.t, r, 200, "işler")
	var jr protocol.JobsResponse
	_ = json.Unmarshal(body, &jr)
	return len(jr.Jobs)
}

func TestMaintenanceWindowAndRollout(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	secret := e.adminCreateKey(map[string]any{"name": "kademe"})
	var agents []*testAgent
	var clients []*http.Client
	var ids []string
	for i := range 4 {
		_, ag := e.enroll(secret, fmt.Sprintf("PC-%03d", i))
		agents = append(agents, ag)
		clients = append(clients, e.agentClient(ag.tlsCert(t)))
		ids = append(ids, ag.id)
	}

	// Şu anda kapalı olan bir pencere: yarın, bir saatliğine.
	tomorrow := e.clock.In(time.UTC).AddDate(0, 0, 1)
	resp, win := admin.do("POST", "/api/v1/maintenance-windows", map[string]any{"name": "Gece", "weekdays": []int{int(tomorrow.Weekday())},
		"start_minute": tomorrow.Hour()*60 + tomorrow.Minute(), "duration_minutes": 60, "timezone": "UTC", "enabled": true}, true)
	expectStatus(t, resp, 200, "pencere")
	resp, _ = admin.do("POST", "/api/v1/maintenance-windows", map[string]any{"name": "", "weekdays": []int{1}, "duration_minutes": 60}, true)
	expectStatus(t, resp, 400, "adsız pencere")

	cmd := map[string]any{"kind": "run_command", "shell": "sh", "command": "true", "machine_ids": ids[:1], "respect_windows": true}
	resp, _ = admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 10000, "max_upload_mb": 100,
		"command_approval": false, "default_expiry_hours": 48}, true)
	expectStatus(t, resp, 200, "aktarım ayarı")
	resp, _ = admin.do("POST", "/api/v1/actions", cmd, true)
	expectStatus(t, resp, 400, "Windows ajanında sh") // örnek ajanlar Windows
	cmd["shell"] = "cmd"
	resp, act := admin.do("POST", "/api/v1/actions", cmd, true)
	expectStatus(t, resp, 201, "pencereye uyan komut")
	if n := e.jobCount(clients[0]); n != 0 {
		t.Fatalf("pencere kapalıyken iş verilmemeli: %d", n)
	}
	if hr := e.heartbeat(clients[0], nil); hr.PendingJobs != 0 {
		t.Errorf("heartbeat de pencereyi dikkate almalı: %d", hr.PendingJobs)
	}
	e.clock = tomorrow.Add(10 * time.Minute)
	e.srv.invalidateWindows()
	if n := e.jobCount(clients[0]); n != 1 {
		t.Fatalf("pencere açıkken iş verilmeli: %d", n)
	}
	expectStatus(t, admin.login("admin", testPassword), 200, "yeniden giriş") // saat ileri alındı, oturum zaman aşımı
	resp, _ = admin.do("DELETE", "/api/v1/maintenance-windows/"+win["id"].(string), nil, true)
	expectStatus(t, resp, 204, "pencere silme")
	rr, _ := e.postAgent(clients[0], fmt.Sprintf(protocol.PathJobStatusFmt, act["id"]), protocol.JobStatusRequest{Status: "succeeded"})
	expectStatus(t, rr, 204, "pencere işi sonucu")

	// Kademeli dağıtım: %50 + %50, ikinci aşama 1 saat sonra, en az %100 başarı.
	ro := map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver", "machine_ids": ids,
		"rollout": map[string]any{"stages": []map[string]any{{"percent": 50, "delay_hours": 0}, {"percent": 50, "delay_hours": 1}},
			"min_success_percent": 100}}
	resp, act = admin.do("POST", "/api/v1/actions", ro, true)
	expectStatus(t, resp, 201, "kademeli aksiyon")
	actID := act["id"].(string)
	var first, second []int
	for i, c := range clients {
		var jr protocol.JobsResponse
		_, body := e.agentGet(c, protocol.PathJobs, nil)
		_ = json.Unmarshal(body, &jr)
		has := false
		for _, j := range jr.Jobs {
			var p struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(j.Payload, &p)
			has = has || p.ID == actID
		}
		if has {
			first = append(first, i)
		} else {
			second = append(second, i)
		}
	}
	if len(first) != 2 || len(second) != 2 {
		t.Fatalf("ilk aşamada 2 makine olmalı: %v / %v", first, second)
	}
	// Süre dolmadan ikinci aşama açılmaz.
	e.srv.RunRollouts(context.Background())
	for _, i := range second {
		if e.jobCount(clients[i]) != 0 {
			t.Fatal("ikinci aşama erken açıldı")
		}
	}
	// Pilot makinelerden biri başarısız: süre dolsa da dağıtım duraklar.
	rr, _ = e.postAgent(clients[first[0]], fmt.Sprintf(protocol.PathJobStatusFmt, actID), protocol.JobStatusRequest{Status: "succeeded"})
	expectStatus(t, rr, 204, "başarılı")
	rr, _ = e.postAgent(clients[first[1]], fmt.Sprintf(protocol.PathJobStatusFmt, actID), protocol.JobStatusRequest{Status: "failed"})
	expectStatus(t, rr, 204, "başarısız")
	e.clock = e.clock.Add(2 * time.Hour)
	e.srv.RunRollouts(context.Background())
	expectStatus(t, admin.login("admin", testPassword), 200, "yeniden giriş")
	resp, out := admin.do("GET", "/api/v1/actions/"+actID, nil, false)
	expectStatus(t, resp, 200, "aksiyon")
	a := out["action"].(map[string]any)
	if !strings.Contains(fmt.Sprint(a["paused_reason"]), "%50") || a["released_stages"].(float64) != 1 {
		t.Fatalf("dağıtım duraklamalı: %v", a)
	}
	for _, i := range second {
		if e.jobCount(clients[i]) != 0 {
			t.Fatal("duraklatılan aşama açılmamalı")
		}
	}
	// Yönetici elle devam ettirir.
	resp, out = admin.do("POST", "/api/v1/actions/"+actID+"/release-next", nil, true)
	expectStatus(t, resp, 200, "elle sonraki aşama")
	if out["released_stages"].(float64) != 2 {
		t.Errorf("iki aşama açılmış olmalı: %v", out)
	}
	for _, i := range second {
		if e.jobCount(clients[i]) != 1 {
			t.Fatal("ikinci aşama makinesi işi almalı")
		}
	}
	resp, _ = admin.do("POST", "/api/v1/actions/"+actID+"/release-next", nil, true)
	expectStatus(t, resp, 409, "açılacak aşama yok")
	_ = agents
}

// fakeSMTP, kimlik doğrulamasız düz SMTP konuşan basit bir test sunucusudur.
type fakeSMTP struct {
	ln   net.Listener
	mu   sync.Mutex
	msgs []string
	rcpt []string
}

func newFakeSMTP(t *testing.T) *fakeSMTP {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	fmt.Fprint(c, "220 test ESMTP\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			fmt.Fprint(c, "250-test\r\n250 8BITMIME\r\n")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, strings.TrimSpace(line[8:]))
			f.mu.Unlock()
			fmt.Fprint(c, "250 OK\r\n")
		case cmd == "DATA":
			fmt.Fprint(c, "354 devam\r\n")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.msgs = append(f.msgs, b.String())
			f.mu.Unlock()
			fmt.Fprint(c, "250 OK\r\n")
		case cmd == "QUIT":
			fmt.Fprint(c, "221 bye\r\n")
			return
		default:
			fmt.Fprint(c, "250 OK\r\n")
		}
	}
}

func (f *fakeSMTP) messages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.msgs...)
}

func TestNotifications(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")

	type hook struct {
		body []byte
		sig  string
	}
	var mu sync.Mutex
	var hooks []hook
	ws := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hooks = append(hooks, hook{b, r.Header.Get("X-Ber-Signature")})
		mu.Unlock()
		w.WriteHeader(204)
	}))
	t.Cleanup(ws.Close)

	webhook := map[string]any{"name": "Olay akışı", "kind": "webhook", "config": map[string]any{"url": ws.URL, "format": "generic"},
		"secret": "imza-anahtari", "events": []string{store.EventActionCompleted}, "enabled": true}
	resp, _ := ro.do("POST", "/api/v1/notifications/channels", webhook, true)
	expectStatus(t, resp, 403, "salt okunur kanal ekleyemez")
	resp, _ = admin.do("POST", "/api/v1/notifications/channels", map[string]any{"name": "x", "kind": "webhook",
		"config": map[string]any{"url": "http://ornek.local/hook"}, "events": []string{}}, true)
	expectStatus(t, resp, 400, "https olmayan webhook")
	resp, _ = admin.do("POST", "/api/v1/notifications/channels", map[string]any{"name": "x", "kind": "webhook",
		"config": map[string]any{"url": ws.URL}, "events": []string{"yok.boyle"}}, true)
	expectStatus(t, resp, 400, "bilinmeyen olay")
	resp, ch := admin.do("POST", "/api/v1/notifications/channels", webhook, true)
	expectStatus(t, resp, 200, "webhook kanalı")
	chID := ch["id"].(string)
	if strings.Contains(fmt.Sprint(ch), "imza-anahtari") || ch["has_secret"] != true {
		t.Fatalf("gizli değer dönmemeli: %v", ch)
	}

	resp, out := admin.do("POST", "/api/v1/notifications/channels/"+chID+"/test", nil, true)
	expectStatus(t, resp, 200, "deneme")
	if out["ok"] != true || len(hooks) != 1 {
		t.Fatalf("deneme bildirimi = %v, %d", out, len(hooks))
	}
	mac := hmac.New(sha256.New, []byte("imza-anahtari"))
	mac.Write(hooks[0].body)
	if hooks[0].sig != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Errorf("imza uyuşmuyor: %s", hooks[0].sig)
	}

	// Tamamlanan aksiyon bir kez bildirilir.
	secret := e.adminCreateKey(map[string]any{"name": "bildirim"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	resp, _ = admin.do("PUT", "/api/v1/settings/transfer", map[string]any{"per_client_kbps": 10000, "max_upload_mb": 100,
		"command_approval": false, "default_expiry_hours": 24}, true)
	expectStatus(t, resp, 200, "aktarım ayarı")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "run_command", "shell": "cmd", "command": "ver",
		"name": "Sürüm kontrolü", "machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 201, "aksiyon")
	actID := act["id"].(string)
	rr, _ := e.postAgent(client, fmt.Sprintf(protocol.PathJobStatusFmt, actID), protocol.JobStatusRequest{Status: "failed"})
	expectStatus(t, rr, 204, "sonuç")
	e.srv.RunNotifications(context.Background())
	e.srv.RunNotifications(context.Background())
	mu.Lock()
	if len(hooks) != 2 {
		t.Fatalf("aksiyon bildirimi bir kez gönderilmeli: %d", len(hooks))
	}
	var ev map[string]any
	_ = json.Unmarshal(hooks[1].body, &ev)
	mu.Unlock()
	if ev["event"] != store.EventActionCompleted || !strings.Contains(ev["title"].(string), "1 hedef başarısız") {
		t.Errorf("olay = %v", ev)
	}

	// E-posta kanalı ve zamanlanmış rapor (ekli).
	smtpSrv := newFakeSMTP(t)
	host, port, _ := net.SplitHostPort(smtpSrv.ln.Addr().String())
	var portNum int
	fmt.Sscan(port, &portNum)
	resp, mailCh := admin.do("POST", "/api/v1/notifications/channels", map[string]any{"name": "BT ekibi", "kind": "email",
		"config": map[string]any{"smtp_host": host, "smtp_port": portNum, "security": "none", "from": "ber@ornek.local",
			"to": []string{"bt@ornek.local"}}, "events": []string{}, "enabled": true}, true)
	expectStatus(t, resp, 200, "e-posta kanalı")
	resp, _ = admin.do("POST", "/api/v1/notifications/schedules", map[string]any{"report": "compliance", "format": "csv",
		"hour": 7, "channel_id": chID}, true)
	expectStatus(t, resp, 400, "webhook'a zamanlanmış rapor")
	at := time.Date(2026, 11, 2, 7, 5, 0, 0, time.UTC)
	resp, _ = admin.do("POST", "/api/v1/notifications/schedules", map[string]any{"report": "compliance", "format": "csv",
		"lang": "tr", "hour": 7, "weekday": int(at.Weekday()), "timezone": "UTC", "channel_id": mailCh["id"]}, true)
	expectStatus(t, resp, 201, "zamanlanmış rapor")
	e.clock = at.Add(-time.Hour)
	e.srv.RunNotifications(context.Background())
	if n := len(smtpSrv.messages()); n != 0 {
		t.Fatalf("vakti gelmeden rapor gönderilmemeli: %d", n)
	}
	e.clock = at
	e.srv.RunNotifications(context.Background())
	e.srv.RunNotifications(context.Background())
	msgs := smtpSrv.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0], "multipart/mixed") || !strings.Contains(msgs[0], ".csv") {
		t.Fatalf("rapor e-postası bir kez ve ekli gitmeli: %d %.400s", len(msgs), strings.Join(msgs, "\n---\n"))
	}

	expectStatus(t, admin.login("admin", testPassword), 200, "yeniden giriş")
	expectStatus(t, ro.login("izleyici", testPassword), 200, "yeniden giriş")
	resp, _ = ro.do("GET", "/api/v1/notifications", nil, false)
	expectStatus(t, resp, 403, "salt okunur ayarları göremez")
	resp, out = admin.do("GET", "/api/v1/notifications", nil, false)
	expectStatus(t, resp, 200, "liste")
	if len(out["items"].([]any)) != 2 || len(out["schedules"].([]any)) != 1 {
		t.Errorf("liste = %v", out)
	}
	resp, _ = admin.do("DELETE", "/api/v1/notifications/channels/"+chID, nil, true)
	expectStatus(t, resp, 204, "kanal silme")
}
