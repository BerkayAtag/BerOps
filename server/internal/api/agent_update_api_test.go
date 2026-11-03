package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestAgentUpdateAction(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("tekniker", "technician")
	secret := e.adminCreateKey(map[string]any{"name": "guncelleme"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	hr := e.heartbeat(client, nil) // eski ajan: yetenek bildirmez

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	tech := e.browser()
	expectStatus(t, tech.login("tekniker", testPassword), 200, "giriş")

	content := bytes.Repeat([]byte("BEROPSAGENT"), 1000)
	resp, msi := admin.upload(map[string]any{"name": "BerOps Agent", "version": "1.3.0", "platform": "windows",
		"installer": "msi"}, "BerOps-Agent-x64.msi", content)
	expectStatus(t, resp, 201, "ajan paketi")
	resp, exe := admin.upload(map[string]any{"name": "Kurulum", "version": "1", "platform": "windows",
		"installer": "exe", "install_command": `"{file}" /S`}, "kur.exe", content)
	expectStatus(t, resp, 201, "exe paketi")

	resp, _ = tech.do("POST", "/api/v1/actions", map[string]any{"kind": "update_agent", "package_id": msi["id"],
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 403, "teknisyen ajan güncelleyemez")
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "update_agent", "package_id": exe["id"],
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 400, "EXE ile ajan güncellenmez")
	resp, out := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "update_agent", "package_id": msi["id"],
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 400, "güncellemeyi desteklemeyen eski ajan")
	if msg, _ := out["message"].(string); !strings.Contains(msg, "1.3 öncesi") {
		t.Errorf("hata iletisi eski ajanı açıklamalı: %v", out)
	}

	host := hostInfo("PC-001")
	host.Capabilities = []string{protocol.CapabilityUpdateAgent}
	r, _ := e.postAgent(client, protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: host})
	expectStatus(t, r, 200, "yetenekli heartbeat")
	resp, act := admin.do("POST", "/api/v1/actions", map[string]any{"kind": "update_agent", "package_id": msi["id"],
		"machine_ids": []string{ag.id}}, true)
	expectStatus(t, resp, 201, "ajan güncellemesi")

	_, raw := e.agentGet(client, protocol.PathJobs, nil)
	var jr protocol.JobsResponse
	_ = json.Unmarshal(raw, &jr)
	if len(jr.Jobs) != 1 {
		t.Fatalf("güncelleme işi verilmeli: %s", raw)
	}
	job, err := jr.Jobs[0].Verify(hr.ActionKey, ag.id, e.clock)
	if err != nil || job.Kind != protocol.JobUpdateAgent || job.Command != "" || job.Package == nil ||
		job.Package.Installer != "msi" || job.Package.SHA256 != msi["file_sha256"] {
		t.Fatalf("imzalı güncelleme işi = %v %+v", err, job)
	}
	// Kayıtta bildirilen yetenek, ilk heartbeat beklenmeden geçerlidir.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	newHost := hostInfo("PC-002")
	newHost.Capabilities = []string{protocol.CapabilityUpdateAgent}
	r, body := e.postAgent(e.agentClient(nil), protocol.PathEnroll, protocol.EnrollRequest{RegistrationKey: secret,
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), Host: newHost})
	expectStatus(t, r, 201, "yetenekli kayıt")
	var er protocol.EnrollResponse
	_ = json.Unmarshal(body, &er)
	resp, _ = admin.do("POST", "/api/v1/actions", map[string]any{"kind": "update_agent", "package_id": msi["id"],
		"machine_ids": []string{er.AgentID}}, true)
	expectStatus(t, resp, 201, "yeni kaydolan ajana güncelleme")

	// Ajan paketi yalnızca açık aksiyon üzerinden indirebilir.
	r, _ = e.agentGet(client, "/agent/v1/packages/"+msi["id"].(string)+"/file?action="+act["id"].(string), nil)
	expectStatus(t, r, 200, "paket indirme")
}

func TestUninstallProtection(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	e.createUser("izleyici", "readonly")
	secret := e.adminCreateKey(map[string]any{"name": "koruma"})
	_, ag := e.enroll(secret, "PC-001")
	client := e.agentClient(ag.tlsCert(t))
	if hr := e.heartbeat(client, nil); hr.UninstallProtection == nil || hr.UninstallProtection.Enabled {
		t.Fatalf("koruma varsayılan olarak kapalı bildirilmeli: %+v", hr.UninstallProtection)
	}

	admin := e.browser()
	expectStatus(t, admin.login("admin", testPassword), 200, "giriş")
	ro := e.browser()
	expectStatus(t, ro.login("izleyici", testPassword), 200, "giriş")

	resp, _ := ro.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": true, "code": "Kaldirma-Kodu-1"}, true)
	expectStatus(t, resp, 403, "salt okunur koruma değiştiremez")
	resp, _ = admin.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": true}, true)
	expectStatus(t, resp, 400, "ilk açılışta kod gerekli")
	resp, _ = admin.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": true, "code": "kisa-kod-11"}, true)
	expectStatus(t, resp, 400, "12 karakterden kısa kod")
	resp, _ = admin.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": true, "code": "Kaldirma-Kodu-1"}, true)
	expectStatus(t, resp, 200, "koruma açıldı")

	e.clock = e.clock.Add(settingsCacheTTL)
	hr := e.heartbeat(client, nil)
	p := hr.UninstallProtection
	if p == nil || !p.Enabled || !p.Allows("Kaldirma-Kodu-1") || p.Allows("yanlis-kod-123") || p.Allows("") {
		t.Fatalf("ajana kodun özeti gitmeli: %+v", p)
	}
	resp, out := ro.do("GET", "/api/v1/settings/agent-protection", nil, false)
	expectStatus(t, resp, 200, "durum")
	if out["enabled"] != true || len(out) != 2 {
		t.Fatalf("konsola özet gönderilmemeli: %v", out)
	}
	// Onay bekleyen ajan özeti almaz (kayıt anahtarını bilen biri özeti kırmaya çalışamasın).
	pendingKey := e.adminCreateKey(map[string]any{"name": "onayli", "require_approval": true})
	_, pending := e.enroll(pendingKey, "PC-002")
	if hr := e.heartbeat(e.agentClient(pending.tlsCert(t)), nil); hr.Status != protocol.StatusPending || hr.UninstallProtection != nil {
		t.Fatalf("onay bekleyen ajana koruma gönderilmemeli: %s %+v", hr.Status, hr.UninstallProtection)
	}
	// Kodsuz kayıt mevcut kodu korur.
	resp, _ = admin.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": true}, true)
	expectStatus(t, resp, 200, "kod değişmeden")
	if hr := e.heartbeat(client, nil); !hr.UninstallProtection.Allows("Kaldirma-Kodu-1") {
		t.Fatal("kodsuz kayıt kodu değiştirmemeli")
	}
	entries, _, err := e.store.ListAudit(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if audit, _ := json.Marshal(entries); bytes.Contains(audit, []byte("Kaldirma-Kodu-1")) {
		t.Fatal("kod denetim kaydına yazılmamalı")
	}
	resp, _ = admin.do("PUT", "/api/v1/settings/agent-protection", map[string]any{"enabled": false}, true)
	expectStatus(t, resp, 200, "koruma kapatıldı")
	if hr := e.heartbeat(client, nil); hr.UninstallProtection == nil || hr.UninstallProtection.Enabled {
		t.Fatalf("kapatma ajana bildirilmeli: %+v", hr.UninstallProtection)
	}
}

func TestAgentCertRenew(t *testing.T) {
	e := newEnv(t)
	e.createUser("admin", "admin")
	secret := e.adminCreateKey(map[string]any{"name": "yenileme"})
	_, ag := e.enroll(secret, "PC-001")
	oldClient := e.agentClient(ag.tlsCert(t))
	newCSR := func() protocol.RenewRequest {
		der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, ag.key)
		return protocol.RenewRequest{CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))}
	}

	r, _ := e.postAgent(e.agentClient(nil), protocol.PathRenew, newCSR())
	expectStatus(t, r, 401, "sertifikasız yenileme")
	r, _ = e.postAgent(oldClient, protocol.PathRenew, newCSR())
	expectStatus(t, r, 409, "yeni sertifika yenilenmez")

	e.clock = e.clock.Add(200 * 24 * time.Hour)
	r, _ = e.postAgent(oldClient, protocol.PathRenew, protocol.RenewRequest{CSRPEM: "çöp"})
	expectStatus(t, r, 400, "geçersiz CSR")
	r, body := e.postAgent(oldClient, protocol.PathRenew, newCSR())
	expectStatus(t, r, 200, "yenileme")
	var rr protocol.RenewResponse
	if err := json.Unmarshal(body, &rr); err != nil {
		t.Fatal(err)
	}
	renewed := &testAgent{key: ag.key, certPEM: []byte(rr.CertificatePEM), id: ag.id}
	cert := renewed.tlsCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.Subject.CommonName != ag.id {
		t.Fatalf("yeni sertifika ajan kimliğini taşımalı: %v %v", err, leaf.Subject)
	}
	m, err := e.store.GetMachine(t.Context(), ag.id)
	if err != nil || m.CertSerial != leaf.SerialNumber.Text(16) || m.CertFingerprint == "" {
		t.Fatalf("makine yeni sertifikayla güncellenmeli: %v %+v", err, m)
	}

	// Geçiş: eski ve yeni sertifika birlikte kabul edilir.
	newClient := e.agentClient(cert)
	for name, c := range map[string]*http.Client{"eski": oldClient, "yeni": newClient} {
		r, _ := e.postAgent(c, protocol.PathHeartbeat, protocol.HeartbeatRequest{Host: hostInfo("PC-001")})
		expectStatus(t, r, 200, name+" sertifikayla heartbeat")
	}
	entries, _, err := e.store.ListAudit(context.Background(), store.AuditFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, en := range entries {
		if en.Action == "agent.cert_renew" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("yenileme denetim kaydı = %d", n)
	}

	// Önceki sertifikayla hemen yeniden yenileme yapılamaz (sınırsız sertifika üretimi önlenir).
	r, _ = e.postAgent(oldClient, protocol.PathRenew, newCSR())
	expectStatus(t, r, 409, "önceki sertifikayla art arda yenileme")

	// CSR başka bir anahtar taşıyorsa kimlik o anahtara taşınamaz.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, other)
	r, _ = e.postAgent(e.agentClient(cert), protocol.PathRenew, protocol.RenewRequest{
		CSRPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))})
	expectStatus(t, r, 400, "başka anahtarlı CSR")

	if _, err := e.store.SetMachineStatus(t.Context(), ag.id, protocol.StatusRevoked); err != nil {
		t.Fatal(err)
	}
	r, _ = e.postAgent(oldClient, protocol.PathRenew, newCSR())
	expectStatus(t, r, 403, "iptal edilen makine yenileyemez")
}
