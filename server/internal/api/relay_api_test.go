package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/relay/relay"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestRelayProxiesAndCaches(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "sube"})

	// Relay kaydı ve sertifikası (berops-server relay create ile aynı adımlar).
	const relayID = "11111111-2222-4333-8444-555555555555"
	rc, err := e.ca.IssueRelayCert(relayID, []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.CreateRelay(context.Background(), relayID, "İzmir", []string{"127.0.0.1"}, rc.Serial, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	relayCert, err := tls.X509KeyPair(rc.CertPEM, rc.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	r, err := relay.New(relay.Config{ServerURL: e.agent.URL, CA: e.ca.Pool(), Cert: relayCert, CacheDir: t.TempDir(),
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	rs := httptest.NewUnstartedServer(r)
	rs.TLS = r.TLSConfig()
	rs.StartTLS()
	t.Cleanup(rs.Close)

	// Ajan relay'e bağlanır; CA pin'i değişmez.
	viaRelay := func(c *http.Client, method, path string, body any, hdr map[string]string) (*http.Response, []byte) {
		t.Helper()
		var rd io.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
		req, _ := http.NewRequest(method, rs.URL+path, rd)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)
		return resp, out
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	resp, body := viaRelay(e.agentClient(nil), "POST", protocol.PathEnroll, protocol.EnrollRequest{
		RegistrationKey: secret, CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		Host: hostInfo("PC-SUBE"),
	}, nil)
	expectStatus(t, resp, 201, "relay üzerinden kayıt")
	var er protocol.EnrollResponse
	_ = json.Unmarshal(body, &er)
	blk, _ := pem.Decode([]byte(er.CertificatePEM))
	agentCert := &tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}
	client := e.agentClient(agentCert)

	resp, body = viaRelay(client, "POST", protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-SUBE")}, nil)
	expectStatus(t, resp, 200, "relay üzerinden heartbeat")
	var hr protocol.HeartbeatResponse
	_ = json.Unmarshal(body, &hr)
	if hr.Status != "active" || len(hr.ActionKey) == 0 {
		t.Fatalf("heartbeat = %s", body)
	}

	// Paket dağıtımı: ilk indirme sunucudan çekilip önbelleğe alınır, ikincisi önbellekten verilir.
	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	content := bytes.Repeat([]byte("ŞUBE"), 5000)
	resp, pkg := admin.upload(map[string]any{"name": "Şube Aracı", "version": "1.0", "platform": "windows", "installer": "msi"}, "arac.msi", content)
	expectStatus(t, resp, 201, "paket")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "deploy_package", "package_id": pkg["id"],
		"machine_ids": []string{er.AgentID}}, true)
	expectStatus(t, resp, 201, "aksiyon")
	dl := fmt.Sprintf(protocol.PathPackageFileFmt, pkg["id"]) + "?action=" + act["id"].(string)
	for i := range 2 {
		resp, got := viaRelay(client, "GET", dl, nil, nil)
		expectStatus(t, resp, 200, "relay indirmesi")
		if !bytes.Equal(got, content) || resp.Header.Get("X-Ber-Relay") != "hit" {
			t.Fatalf("indirme %d: %d bayt, başlık %q", i, len(got), resp.Header.Get("X-Ber-Relay"))
		}
	}
	if r.Misses != 1 || r.Hits != 1 {
		t.Errorf("önbellek: %d kaçırma, %d isabet", r.Misses, r.Hits)
	}
	// Yetkisiz indirme (aksiyonsuz) sunucunun yanıtıyla reddedilir.
	resp, _ = viaRelay(client, "GET", fmt.Sprintf(protocol.PathPackageFileFmt, pkg["id"])+"?action="+er.AgentID, nil, nil)
	expectStatus(t, resp, 404, "aksiyonsuz relay indirmesi")

	// Ajan başlığı sahteleyemez: doğrudan sunucuya giden istekte başlık yok sayılır,
	// relay ise ajanın gönderdiği başlığı siler.
	other := base64.StdEncoding.EncodeToString(blk.Bytes)
	resp, _ = viaRelay(e.agentClient(nil), "GET", protocol.PathJobs, nil, map[string]string{HeaderAgentCert: other})
	expectStatus(t, resp, 401, "sertifikasız ajan başlıkla kimlik kazanamaz")
	relayDirect := e.agentClient(&relayCert)
	req, _ := http.NewRequest("GET", e.agent.URL+protocol.PathJobs, nil)
	resp, err = relayDirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	expectStatus(t, resp, 401, "ajan sertifikası iletmeyen relay")

	resp, out := admin.do("GET", "/api/v1/relays", nil, false)
	expectStatus(t, resp, 200, "relay listesi")
	if it := out["items"].([]any)[0].(map[string]any); it["last_seen_at"] == nil || it["name"] != "İzmir" {
		t.Errorf("relay kaydı = %v", it)
	}
	resp, _ = admin.do("DELETE", "/api/v1/relays/"+relayID, nil, true)
	expectStatus(t, resp, 204, "relay iptali")
	resp, _ = viaRelay(client, "POST", protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-SUBE")}, nil)
	expectStatus(t, resp, 401, "iptal edilen relay")
}
