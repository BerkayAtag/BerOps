package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
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
	})
}

// agentFromTLS, doğrulanmış istemci sertifikasından makine kaydını bulur. Sertifika seri
// numarası kayıttakiyle eşleşmeli ve makine reddedilmiş/iptal edilmiş olmamalıdır.
func (s *Server) agentFromTLS(w http.ResponseWriter, r *http.Request) (*store.Machine, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Geçerli bir ajan sertifikası gerekli")
		return nil, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	id := leaf.Subject.CommonName
	if !validUUID(id) {
		writeError(w, http.StatusUnauthorized, codeAgentUnknown, "Ajan tanınmıyor")
		return nil, false
	}
	m, err := s.store.GetMachine(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusUnauthorized, codeAgentUnknown, "Ajan tanınmıyor")
		return nil, false
	}
	if err != nil {
		s.log.Error("makine okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	if m.CertSerial != leaf.SerialNumber.Text(16) {
		writeError(w, http.StatusUnauthorized, codeAgentRevoked, "Ajan sertifikası artık geçerli değil")
		return nil, false
	}
	if m.Status == protocol.StatusRejected || m.Status == protocol.StatusRevoked {
		writeError(w, http.StatusForbidden, codeAgentRevoked, "Ajan reddedilmiş veya iptal edilmiş")
		return nil, false
	}
	return m, true
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
	writeJSON(w, http.StatusOK, protocol.HeartbeatResponse{
		Status:           m.Status,
		HeartbeatSeconds: s.cfg.Agent.HeartbeatSeconds,
		ServerTime:       s.now().UTC(),
	})
}
