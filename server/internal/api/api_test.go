package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/auth"
	"github.com/BerkayAtag/BerOps/server/internal/config"
	"github.com/BerkayAtag/BerOps/server/internal/pki"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/server/internal/store/storetest"
	"github.com/BerkayAtag/BerOps/shared/protocol"
	"github.com/BerkayAtag/BerOps/shared/tlspin"
)

const testPassword = "test-parolasi-uzun-123"

type env struct {
	t       *testing.T
	srv     *Server
	store   *store.Store
	ca      *pki.CA
	console *httptest.Server
	agent   *httptest.Server
	clock   time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	st := storetest.New(t)
	ca, err := pki.NewInMemoryCA("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.DatabaseURL = "test"
	cfg.DataDir = t.TempDir()
	srv, err := New(cfg, st, ca, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, srv: srv, store: st, ca: ca, clock: time.Now()}
	srv.now = func() time.Time { return e.clock }

	e.console = httptest.NewTLSServer(srv.ConsoleHandler())
	t.Cleanup(e.console.Close)

	serverCert, err := ca.IssueServerCert([]string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	e.agent = httptest.NewUnstartedServer(srv.AgentHandler())
	e.agent.TLS = srv.AgentTLSConfig(serverCert)
	e.agent.StartTLS()
	t.Cleanup(e.agent.Close)
	return e
}

func (e *env) createUser(username, role string) {
	e.t.Helper()
	h, err := auth.HashPassword(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.store.CreateLocalUser(context.Background(), username, "", h, role, false); err != nil {
		e.t.Fatal(err)
	}
}

// browser, çerez kavanozu olan ve CSRF token'ını hatırlayan bir konsol istemcisidir.
type browser struct {
	e    *env
	c    *http.Client
	csrf string
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := *e.console.Client() // Client() her seferinde aynı işaretçiyi döner; kopyalanmazsa çerezler paylaşılır
	c.Jar = jar
	return &browser{e: e, c: &c}
}

func (b *browser) do(method, path string, body any, withCSRF bool) (*http.Response, map[string]any) {
	b.e.t.Helper()
	var rd io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rd = bytes.NewReader(buf)
	}
	req, _ := http.NewRequest(method, b.e.console.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if withCSRF {
		req.Header.Set(CSRFHeader, b.csrf)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (b *browser) login(username, password string) *http.Response {
	b.e.t.Helper()
	resp, out := b.do("POST", "/api/v1/auth/login", map[string]string{"username": username, "password": password}, false)
	if tok, ok := out["csrf_token"].(string); ok {
		b.csrf = tok
	}
	return resp
}

func expectStatus(t *testing.T, resp *http.Response, want int, ctx string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: durum %d beklenirdi, %d geldi", ctx, want, resp.StatusCode)
	}
}

func TestLoginLogoutFlow(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	b := e.browser()

	expectStatus(t, b.login("admin", "yanlis-parola-xyz"), 401, "yanlış parola")
	resp, _ := b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 401, "giriş yapmadan me")

	resp = b.login("ADMIN", testPassword)
	expectStatus(t, resp, 200, "doğru parola (büyük harf kullanıcı adı)")
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("oturum çerezi güvenli değil: %+v", cookie)
	}
	if b.csrf == "" {
		t.Fatal("girişte CSRF token dönmeli")
	}

	resp, me := b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 200, "me")
	if me["user"].(map[string]any)["role"] != "admin" {
		t.Errorf("rol admin olmalı: %v", me)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Error("güvenlik başlıkları eksik")
	}

	resp, out := b.do("POST", "/api/v1/auth/logout", nil, false)
	expectStatus(t, resp, 403, "CSRF olmadan çıkış")
	if out["code"] != codeCSRF {
		t.Errorf("hata kodu %s olmalı: %v", codeCSRF, out)
	}
	resp, _ = b.do("POST", "/api/v1/auth/logout", nil, true)
	expectStatus(t, resp, 204, "çıkış")
	resp, _ = b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 401, "çıkıştan sonra me")
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	b := e.browser()
	for i := 0; i < 5; i++ {
		expectStatus(t, b.login("admin", "yanlis-parola-xyz"), 401, "yanlış parola")
	}
	resp := b.login("admin", testPassword)
	expectStatus(t, resp, 429, "kilitlenmiş hesap doğru parolayla bile")
	if resp.Header.Get("Retry-After") == "" {
		t.Error("Retry-After başlığı olmalı")
	}
	e.clock = e.clock.Add(16 * time.Minute)
	expectStatus(t, b.login("admin", testPassword), 200, "pencere dolduktan sonra")
}

func TestLoginRequiresJSON(t *testing.T) {
	e := newEnv(t)
	resp, err := e.console.Client().Post(e.console.URL+"/api/v1/auth/login",
		"application/x-www-form-urlencoded", strings.NewReader("username=a&password=b"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expectStatus(t, resp, 415, "form gövdesi")
}

func TestSessionIdleTimeout(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	b := e.browser()
	expectStatus(t, b.login("admin", testPassword), 200, "giriş")
	e.clock = e.clock.Add(29 * time.Minute)
	resp, _ := b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 200, "boşta kalma süresi dolmadan")
	e.clock = e.clock.Add(31 * time.Minute)
	resp, _ = b.do("GET", "/api/v1/auth/me", nil, false)
	expectStatus(t, resp, 401, "boşta kalma süresi dolduktan sonra")
}

// Spesifikasyon §7.2: yetki kontrolü API düzeyinde zorunlu.
func TestRBACEnforcedAtAPI(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("teknisyen", "technician")
	e.createUser("izleyici", "readonly")

	newKey := map[string]any{"name": "test"}
	cases := []struct {
		user        string
		method      string
		path        string
		body        any
		want        int
		description string
	}{
		{"izleyici", "GET", "/api/v1/machines", nil, 200, "salt okunur makine listesini görebilir"},
		{"izleyici", "GET", "/api/v1/server-info", nil, 200, "salt okunur sunucu bilgisini görebilir"},
		{"izleyici", "GET", "/api/v1/audit", nil, 200, "salt okunur denetim kaydını görebilir"},
		{"izleyici", "GET", "/api/v1/registration-keys", nil, 403, "salt okunur kayıt anahtarlarını göremez"},
		{"izleyici", "POST", "/api/v1/registration-keys", newKey, 403, "salt okunur anahtar oluşturamaz"},
		{"izleyici", "POST", "/api/v1/machines/00000000-0000-4000-8000-000000000000/approve", nil, 403, "salt okunur makine onaylayamaz"},
		{"teknisyen", "GET", "/api/v1/machines", nil, 200, "teknisyen makine listesini görebilir"},
		{"teknisyen", "POST", "/api/v1/registration-keys", newKey, 403, "teknisyen anahtar oluşturamaz"},
		{"teknisyen", "POST", "/api/v1/machines/00000000-0000-4000-8000-000000000000/reject", nil, 403, "teknisyen makine reddedemez"},
		{"admin", "POST", "/api/v1/registration-keys", newKey, 201, "admin anahtar oluşturabilir"},
		{"admin", "POST", "/api/v1/machines/00000000-0000-4000-8000-000000000000/approve", nil, 404, "admin için izin var, makine yok"},
	}
	browsers := map[string]*browser{}
	for _, u := range []string{"admin", "teknisyen", "izleyici"} {
		browsers[u] = e.browser()
		expectStatus(t, browsers[u].login(u, testPassword), 200, u+" girişi")
	}
	for _, c := range cases {
		resp, _ := browsers[c.user].do(c.method, c.path, c.body, true)
		if resp.StatusCode != c.want {
			t.Errorf("%s: %s %s → %d, beklenen %d", c.description, c.method, c.path, resp.StatusCode, c.want)
		}
	}

	entries, _, err := e.store.ListAudit(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	denied := 0
	for _, en := range entries {
		if en.Action == "authz.denied" {
			denied++
		}
	}
	if denied != 5 {
		t.Errorf("reddedilen 5 istek denetim kaydına yazılmalı, %d bulundu", denied)
	}
}

// --- Ajan ---

type testAgent struct {
	key     *ecdsa.PrivateKey
	certPEM []byte
	id      string
}

func (e *env) agentClient(cert *tls.Certificate) *http.Client {
	e.t.Helper()
	cfg, err := tlspin.Config(e.ca.Fingerprint(), "127.0.0.1")
	if err != nil {
		e.t.Fatal(err)
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 10 * time.Second}
}

func (e *env) postAgent(c *http.Client, path string, body any) (*http.Response, []byte) {
	e.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := c.Post(e.agent.URL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

func hostInfo(name string) protocol.HostInfo {
	return protocol.HostInfo{
		Hostname: name, OSPlatform: "windows", OSName: "Windows 11 Pro", OSVersion: "23H2",
		OSBuild: "10.0.22631.4460", Arch: "amd64", IPAddresses: []string{"10.0.0.5"}, AgentVersion: "0.1.0",
	}
}

func (e *env) enroll(regKey, hostname string) (*http.Response, *testAgent) {
	e.t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	resp, body := e.postAgent(e.agentClient(nil), protocol.PathEnroll, protocol.EnrollRequest{
		RegistrationKey: regKey,
		CSRPEM:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		Host:            hostInfo(hostname),
	})
	if resp.StatusCode != http.StatusCreated {
		return resp, nil
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		e.t.Fatal(err)
	}
	return resp, &testAgent{key: key, certPEM: []byte(er.CertificatePEM), id: er.AgentID}
}

func (a *testAgent) tlsCert(t *testing.T) *tls.Certificate {
	b, _ := pem.Decode(a.certPEM)
	if b == nil {
		t.Fatal("ajan sertifikası PEM değil")
	}
	return &tls.Certificate{Certificate: [][]byte{b.Bytes}, PrivateKey: a.key}
}

func (e *env) adminCreateKey(body map[string]any) string {
	e.t.Helper()
	b := e.browser()
	expectStatus(e.t, b.login("admin", testPassword), 200, "admin girişi")
	resp, out := b.do("POST", "/api/v1/registration-keys", body, true)
	expectStatus(e.t, resp, 201, "anahtar oluşturma")
	secret, _ := out["secret"].(string)
	install := out["install"].(map[string]any)
	if !strings.Contains(install["windows"].(string), e.ca.Fingerprint()) {
		e.t.Error("kurulum komutu CA parmak izini içermeli")
	}
	return secret
}

func TestAgentEnrollAndHeartbeat(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "pilot", "max_uses": 2})

	resp, _ := e.enroll("berreg_yanlis", "PC-001")
	expectStatus(t, resp, 401, "yanlış kayıt anahtarı")

	resp, ag := e.enroll(secret, "PC-001")
	expectStatus(t, resp, 201, "kayıt")

	// Sertifikasız heartbeat reddedilir.
	r, _ := e.postAgent(e.agentClient(nil), protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-001")})
	expectStatus(t, r, 401, "sertifikasız heartbeat")

	e.clock = e.clock.Add(time.Minute)
	client := e.agentClient(ag.tlsCert(t))
	hb := protocol.HeartbeatRequest{Host: hostInfo("PC-001-YENI"), AgentStartedAt: e.clock.Add(-time.Hour)}
	hb.Host.OSPlatform = "darwin" // platform değişikliği yok sayılmalı
	r, body := e.postAgent(client, protocol.PathHeartbeat, hb)
	expectStatus(t, r, 200, "heartbeat")
	var hr protocol.HeartbeatResponse
	_ = json.Unmarshal(body, &hr)
	if hr.Status != protocol.StatusActive || hr.HeartbeatSeconds != 60 {
		t.Errorf("beklenmeyen heartbeat yanıtı: %+v", hr)
	}
	m, err := e.store.GetMachine(context.Background(), ag.id)
	if err != nil {
		t.Fatal(err)
	}
	if m.Hostname != "PC-001-YENI" || m.OSPlatform != "windows" || m.LastSeenAt == nil ||
		!m.LastSeenAt.Equal(e.clock.Truncate(time.Microsecond)) {
		t.Errorf("heartbeat makine kaydını güncellemeli: %+v", m)
	}

	// Anahtar 2 kullanımlık: ikinci kayıt başarılı, üçüncüsü reddedilir.
	resp, _ = e.enroll(secret, "PC-002")
	expectStatus(t, resp, 201, "ikinci kayıt")
	resp, _ = e.enroll(secret, "PC-003")
	expectStatus(t, resp, 401, "kullanım hakkı bitmiş anahtar")

	// Reddedilen makinenin heartbeat'i 403 alır.
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "admin girişi")
	resp, _ = admin.do("POST", "/api/v1/machines/"+ag.id+"/reject", nil, true)
	expectStatus(t, resp, 200, "makineyi reddet")
	r, _ = e.postAgent(client, protocol.PathHeartbeat, hb)
	expectStatus(t, r, 403, "reddedilmiş makine heartbeat")
}

func TestAgentWithForeignCertRejected(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "pilot"})
	_, ag := e.enroll(secret, "PC-001")

	// Başka bir CA'nın imzaladığı, aynı ajan ID'sini taşıyan sertifika kabul edilmez. Go istemcisi
	// sunucunun kabul ettiği CA listesinde olmayan sertifikayı hiç göndermez; başka bir istemci
	// gönderse de TLS el sıkışması başarısız olur. Her iki durumda da kimlik doğrulanmamalıdır.
	other, _ := pki.NewInMemoryCA("Sahte CA")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	forged, err := other.SignAgentCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), ag.id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	fa := &testAgent{key: key, certPEM: forged.PEM, id: ag.id}
	buf, _ := json.Marshal(protocol.HeartbeatRequest{Host: hostInfo("PC-001")})
	fresp, err := e.agentClient(fa.tlsCert(t)).Post(e.agent.URL+protocol.PathHeartbeat, "application/json", bytes.NewReader(buf))
	if err == nil {
		fresp.Body.Close()
		expectStatus(t, fresp, 401, "sahte CA sertifikası")
	}

	// İstemci sahte sertifikayı zorla gönderirse sunucu el sıkışmayı reddetmeli.
	forcedCfg, _ := tlspin.Config(e.ca.Fingerprint(), "127.0.0.1")
	fc := fa.tlsCert(t)
	forcedCfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return fc, nil }
	forced := &http.Client{Transport: &http.Transport{TLSClientConfig: forcedCfg}, Timeout: 10 * time.Second}
	if fr, err := forced.Post(e.agent.URL+protocol.PathHeartbeat, "application/json", bytes.NewReader(buf)); err == nil {
		fr.Body.Close()
		t.Fatalf("zorla gönderilen sahte sertifika el sıkışmada reddedilmeliydi, durum %d", fr.StatusCode)
	}

	// Aynı CA'dan ama kayıttaki seri numarasından farklı bir sertifika da reddedilir.
	reissued, err := e.ca.SignAgentCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), ag.id, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ra := &testAgent{key: key, certPEM: reissued.PEM, id: ag.id}
	r, _ := e.postAgent(e.agentClient(ra.tlsCert(t)), protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-001")})
	expectStatus(t, r, 401, "eski/farklı seri numaralı sertifika")
}

func TestAgentEnrollRequiresApproval(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "onaylı", "require_approval": true})
	resp, ag := e.enroll(secret, "MAC-001")
	expectStatus(t, resp, 201, "kayıt")

	m, _ := e.store.GetMachine(context.Background(), ag.id)
	if m.Status != protocol.StatusPending {
		t.Fatalf("durum pending olmalı: %s", m.Status)
	}
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "admin girişi")
	r, _ := admin.do("POST", "/api/v1/machines/"+ag.id+"/approve", nil, true)
	expectStatus(t, r, 200, "onay")
	r, _ = admin.do("POST", "/api/v1/machines/"+ag.id+"/approve", nil, true)
	expectStatus(t, r, 409, "ikinci onay")
	m, _ = e.store.GetMachine(context.Background(), ag.id)
	if m.Status != protocol.StatusActive {
		t.Fatalf("onay sonrası durum active olmalı: %s", m.Status)
	}
}

func TestEnrollRejectsInvalidCSRWithoutConsumingKey(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "tek", "max_uses": 1})
	r, _ := e.postAgent(e.agentClient(nil), protocol.PathEnroll, protocol.EnrollRequest{
		RegistrationKey: secret, CSRPEM: "bozuk", Host: hostInfo("PC-001"),
	})
	expectStatus(t, r, 400, "bozuk CSR")
	resp, _ := e.enroll(secret, "PC-001")
	expectStatus(t, resp, 201, "anahtar bozuk CSR yüzünden harcanmamalı")
}
