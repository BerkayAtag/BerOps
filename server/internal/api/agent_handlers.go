package api

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/auth"
	"github.com/BerkayAtag/BerOps/server/internal/pki"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

const maxAgentBody = 64 << 10 // 64 KiB; envanter yüklemeleri ayrı uç noktalardan yapılır

func validHost(h protocol.HostInfo) error {
	if strings.TrimSpace(h.Hostname) == "" || len(h.Hostname) > 255 {
		return errors.New("hostname 1-255 karakter olmalı")
	}
	if h.OSPlatform != protocol.PlatformWindows && h.OSPlatform != protocol.PlatformDarwin {
		return errors.New("desteklenmeyen platform: " + h.OSPlatform)
	}
	if len(h.IPAddresses) > 64 {
		return errors.New("çok fazla IP adresi")
	}
	if len(h.Capabilities) > 32 {
		return errors.New("çok fazla yetenek")
	}
	for _, c := range h.Capabilities {
		if c == "" || len(c) > 64 {
			return errors.New("geçersiz yetenek adı")
		}
	}
	return nil
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	limitKey := "enroll:" + ip
	if ok, _ := s.enrollLimiter.Allowed(limitKey); !ok {
		writeError(w, http.StatusTooManyRequests, codeRateLimited, "Çok fazla başarısız kayıt denemesi")
		return
	}
	var req protocol.EnrollRequest
	if !decodeJSON(w, r, &req, maxAgentBody) {
		return
	}
	if err := validHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}

	agentID, err := newUUID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// CSR, kayıt anahtarı tüketilmeden önce imzalanır: geçersiz bir CSR anahtarın
	// kullanım hakkını boşa harcamaz. İmzalanan sertifika anahtar geçersizse atılır.
	cert, err := s.ca.SignAgentCSR([]byte(req.CSRPEM), agentID, s.cfg.Agent.CertValidity.D())
	if err != nil {
		writeError(w, http.StatusBadRequest, codeEnrollInvalidCSR, err.Error())
		return
	}

	now := s.now()
	key, err := s.store.ConsumeRegistrationKey(r.Context(), auth.HashToken(req.RegistrationKey), now)
	if errors.Is(err, store.ErrNotFound) {
		s.enrollLimiter.Fail(limitKey)
		s.audit(r.Context(), store.AuditEntry{
			ActorType: store.ActorAgent, ActorName: req.Host.Hostname, Action: "agent.enroll",
			Result: store.ResultDenied, Detail: "geçersiz kayıt anahtarı", SourceIP: ip,
		})
		writeError(w, http.StatusUnauthorized, codeEnrollInvalidKey, "Kayıt anahtarı geçersiz, süresi dolmuş veya kullanım hakkı bitmiş")
		return
	}
	if err != nil {
		s.log.Error("kayıt anahtarı doğrulanamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}

	status := protocol.StatusActive
	if key.RequireApproval {
		status = protocol.StatusPending
	}
	m, err := s.store.CreateMachine(r.Context(), store.NewMachine{
		ID: agentID, Status: status, Host: req.Host,
		CertSerial: cert.Serial, CertFingerprint: cert.Fingerprint, CertExpiresAt: cert.NotAfter,
		RegistrationKeyID: key.ID, EnrolledAt: now,
	})
	if err != nil {
		s.log.Error("makine kaydı oluşturulamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorAgent, ActorID: m.ID, ActorName: m.Hostname, Action: "agent.enroll",
		TargetType: "machine", TargetID: m.ID, Result: store.ResultSuccess, SourceIP: ip,
		Params: map[string]any{"registration_key": key.Name, "status": status, "platform": m.OSPlatform},
	})
	s.log.Info("ajan kaydoldu", "ajan", m.ID, "hostname", m.Hostname, "durum", status)

	writeJSON(w, http.StatusCreated, protocol.EnrollResponse{
		AgentID:          m.ID,
		Status:           status,
		CertificatePEM:   string(cert.PEM),
		CACertificatePEM: string(s.ca.CertPEM),
		HeartbeatSeconds: s.cfg.Agent.HeartbeatSeconds,
		ActionKey:        s.actionPublicKey(),
	})
}

// agentFromTLS, doğrulanmış istemci sertifikasından makine kaydını bulur. Sertifika seri
// numarası kayıttakiyle eşleşmeli ve makine reddedilmiş/iptal edilmiş olmamalıdır.
func (s *Server) agentFromTLS(w http.ResponseWriter, r *http.Request) (*store.Machine, bool) {
	m, _, ok := s.agentWithCert(w, r)
	return m, ok
}

// agentWithCert, agentFromTLS gibidir; ayrıca ajanın sunduğu (relay üzerinden geldiyse relay'in
// ilettiği) sertifikayı döner.
func (s *Server) agentWithCert(w http.ResponseWriter, r *http.Request) (*store.Machine, *x509.Certificate, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Geçerli bir ajan sertifikası gerekli")
		return nil, nil, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if strings.HasPrefix(leaf.Subject.CommonName, pki.RelayPrefix) {
		// İstek bir relay üzerinden geldi: relay doğrulanır, ajanın sertifikası relay'in
		// eklediği başlıktan alınır ve CA'ya göre yeniden doğrulanır.
		agent, ok := s.agentViaRelay(w, r, leaf)
		if !ok {
			return nil, nil, false
		}
		leaf = agent
	}
	id := leaf.Subject.CommonName
	if !validUUID(id) {
		writeError(w, http.StatusUnauthorized, codeAgentUnknown, "Ajan tanınmıyor")
		return nil, nil, false
	}
	m, err := s.store.GetMachine(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, codeAgentUnknown, "Ajan tanınmıyor")
		return nil, nil, false
	}
	if err != nil {
		s.log.Error("makine okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, nil, false
	}
	// Yenilemeden sonra önceki sertifika, kendi süresi bitene kadar kabul edilir (TLS süresini
	// zaten doğrular); ajan yeni sertifikayı kaydedemediyse kilitlenmez.
	if serial := leaf.SerialNumber.Text(16); m.CertSerial != serial && (m.PrevCertSerial == "" || m.PrevCertSerial != serial) {
		writeError(w, http.StatusUnauthorized, codeAgentRevoked, "Ajan sertifikası artık geçerli değil")
		return nil, nil, false
	}
	if m.Status == protocol.StatusRejected || m.Status == protocol.StatusRevoked {
		writeError(w, http.StatusForbidden, codeAgentRevoked, "Ajan reddedilmiş veya iptal edilmiş")
		return nil, nil, false
	}
	return m, leaf, true
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	m, ok := s.agentFromTLS(w, r)
	if !ok {
		return
	}
	var req protocol.HeartbeatRequest
	if !decodeJSON(w, r, &req, maxAgentBody) {
		return
	}
	// Platform kayıttan sonra değişemez; heartbeat'teki değer yok sayılır.
	req.Host.OSPlatform = m.OSPlatform
	if err := validHost(req.Host); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	if len(req.Errors) > 20 {
		req.Errors = req.Errors[:20]
	}
	m, err := s.store.RecordHeartbeat(r.Context(), m.ID, req, s.now())
	if err != nil {
		s.log.Error("heartbeat kaydedilemedi", "ajan", m.ID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	resp := protocol.HeartbeatResponse{
		Status:           m.Status,
		HeartbeatSeconds: s.cfg.Agent.HeartbeatSeconds,
		ServerTime:       s.now().UTC(),
	}
	if set, err := s.agentSettings(r); err == nil {
		resp.Settings = &set
	} else {
		s.log.Warn("ajan ayarları okunamadı", "hata", err)
	}
	if err := s.inventoryInstructions(r, m.ID, req.InventoryHashes, &resp); err != nil {
		s.log.Warn("envanter durumu okunamadı", "ajan", m.ID, "hata", err)
	}
	resp.ActionKey = s.actionPublicKey()
	// Koruma özeti yalnızca onaylı ajanlara gönderilir: kayıt anahtarıyla kaydolup onay bekleyen
	// sahte bir ajan, özeti çevrimdışı kırmak için alamaz.
	if m.Status == protocol.StatusActive {
		if p, err := s.uninstallProtection(r); err == nil {
			resp.UninstallProtection = p
		} else {
			s.log.Warn("kaldırma koruması okunamadı", "hata", err)
		}
	}
	s.heartbeatRemote(r, m, &resp)
	if m.Status == protocol.StatusActive {
		if jobs, err := s.machineJobs(r.Context(), m); err == nil {
			resp.PendingJobs = len(jobs)
		} else {
			s.log.Warn("bekleyen işler okunamadı", "ajan", m.ID, "hata", err)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// renewCooldown, önceki sertifikayla yeniden yenileme için geçmesi gereken süredir.
const renewCooldown = time.Hour

// handleRenew, ajan sertifikasını yeniler. Yalnızca sunulan sertifikanın ömrünün yarısından
// azı kaldığında ve CSR aynı anahtarı taşıdığında yenilenir. Önceki sertifikayla yenileme
// (ajan yeni sertifikayı kaydedemediyse) en çok saatte bir yapılabilir.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	m, leaf, ok := s.agentWithCert(w, r)
	if !ok {
		return
	}
	now := s.now()
	if lifetime := leaf.NotAfter.Sub(leaf.NotBefore); leaf.NotAfter.Sub(now) > lifetime/2 {
		writeError(w, http.StatusConflict, codeConflict, "Sertifika henüz yenilenecek kadar eski değil")
		return
	}
	presented := leaf.SerialNumber.Text(16)
	validity := s.cfg.Agent.CertValidity.D()
	// Geçerlilik zamanları CA'nın saatiyle yazılır; bekleme süresi de aynı saatle ölçülür.
	if presented != m.CertSerial && time.Until(m.CertExpiresAt) > validity-renewCooldown {
		writeError(w, http.StatusConflict, codeConflict, "Sertifika az önce yenilendi; yeni sertifikayı kullanın")
		return
	}
	var req protocol.RenewRequest
	if !decodeJSON(w, r, &req, maxAgentBody) {
		return
	}
	// Anahtar değişmez: CSR, sunulan sertifikanın anahtarını taşımalıdır. Aksi hâlde ajan
	// sertifikasını gören biri (ör. ele geçirilmiş relay) kimliği kendi anahtarına taşıyabilirdi.
	if !csrMatchesKey([]byte(req.CSRPEM), leaf.PublicKey) {
		writeError(w, http.StatusBadRequest, codeEnrollInvalidCSR, "CSR mevcut sertifikanın anahtarıyla üretilmeli")
		return
	}
	cert, err := s.ca.SignAgentCSR([]byte(req.CSRPEM), m.ID, validity)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeEnrollInvalidCSR, err.Error())
		return
	}
	err = s.store.RenewMachineCert(r.Context(), m.ID, presented, cert.Serial, cert.Fingerprint, cert.NotAfter)
	if errors.Is(err, store.ErrNotFound) {
		// Eşzamanlı başka bir yenileme sunulan sertifikayı geçersiz kıldı.
		writeError(w, http.StatusConflict, codeConflict, "Sertifika bu sırada yenilendi")
		return
	}
	if err != nil {
		s.log.Error("ajan sertifikası kaydedilemedi", "ajan", m.ID, "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorAgent, ActorID: m.ID, ActorName: m.Hostname, Action: "agent.cert_renew",
		TargetType: "machine", TargetID: m.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"expires_at": cert.NotAfter},
	})
	s.log.Info("ajan sertifikası yenilendi", "ajan", m.ID, "geçerlilik", cert.NotAfter)
	writeJSON(w, http.StatusOK, protocol.RenewResponse{CertificatePEM: string(cert.PEM)})
}

// csrMatchesKey, PEM CSR'ın imzasının geçerli ve açık anahtarının key ile aynı olduğunu döner.
func csrMatchesKey(csrPEM []byte, key crypto.PublicKey) bool {
	blk, _ := pem.Decode(csrPEM)
	if blk == nil || blk.Type != "CERTIFICATE REQUEST" {
		return false
	}
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return false
	}
	pub, ok := csr.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && pub.Equal(key)
}
