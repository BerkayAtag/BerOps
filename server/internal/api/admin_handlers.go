package api

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/auth"
	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
	"github.com/BerkayAtag/BerOps/shared/version"
)

type serverInfoResponse struct {
	Version       string `json:"version"`
	AgentURL      string `json:"agent_url"`
	CAFingerprint string `json:"ca_fingerprint"`
}

// agentURL, ajanların bağlanacağı adrestir (ajan sertifikasındaki ilk ana makine adı).
func (s *Server) agentURL() string {
	_, port, err := net.SplitHostPort(s.cfg.Agent.Listen)
	if err != nil || port == "" {
		port = "52311"
	}
	return "https://" + net.JoinHostPort(s.cfg.Agent.Hostnames[0], port)
}

func (s *Server) handleServerInfo(w http.ResponseWriter, _ *http.Request, _ *store.Session) {
	writeJSON(w, http.StatusOK, serverInfoResponse{
		Version: version.Version, AgentURL: s.agentURL(), CAFingerprint: s.ca.Fingerprint(),
	})
}

type createRegKeyRequest struct {
	Name            string `json:"name"`
	RequireApproval bool   `json:"require_approval"`
	MaxUses         *int   `json:"max_uses"`
	ExpiresInHours  *int   `json:"expires_in_hours"`
}

type installCommands struct {
	Windows string `json:"windows"`
	MacOS   string `json:"macos"`
}

type createRegKeyResponse struct {
	Key     store.RegistrationKey `json:"key"`
	Secret  string                `json:"secret"`
	Install installCommands       `json:"install"`
}

func (s *Server) handleListRegKeys(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	keys, err := s.store.ListRegistrationKeys(r.Context())
	if err != nil {
		s.log.Error("kayıt anahtarları okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

func (s *Server) handleCreateRegKey(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createRegKeyRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Ad 1-100 karakter olmalı")
		return
	}
	if req.MaxUses != nil && *req.MaxUses <= 0 {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kullanım sayısı pozitif olmalı")
		return
	}
	var expires *time.Time
	if req.ExpiresInHours != nil {
		if *req.ExpiresInHours <= 0 || *req.ExpiresInHours > 24*365 {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçerlilik süresi 1 saat ile 1 yıl arasında olmalı")
			return
		}
		t := s.now().Add(time.Duration(*req.ExpiresInHours) * time.Hour)
		expires = &t
	}
	secret, prefix, err := auth.NewRegistrationKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	key, err := s.store.CreateRegistrationKey(r.Context(), store.NewRegistrationKey{
		Name: req.Name, KeyHash: auth.HashToken(secret), KeyPrefix: prefix,
		RequireApproval: req.RequireApproval, MaxUses: req.MaxUses, ExpiresAt: expires, CreatedBy: sess.User.ID,
	})
	if err != nil {
		s.log.Error("kayıt anahtarı oluşturulamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "regkey.create", TargetType: "registration_key", TargetID: key.ID, Result: store.ResultSuccess,
		SourceIP: clientIP(r),
		Params:   map[string]any{"name": key.Name, "require_approval": key.RequireApproval, "max_uses": key.MaxUses},
	})
	writeJSON(w, http.StatusCreated, createRegKeyResponse{
		Key:     *key,
		Secret:  secret,
		Install: s.installCommands(secret),
	})
}

// installCommands, kurulum paketleri için sunucu adresi, anahtar ve CA parmak izi gömülü
// komutları üretir. macOS paketi kurulduktan sonra daemon yapılandırmayı bekler; configure
// komutu yazdığı anda kayıt başlar.
func (s *Server) installCommands(secret string) installCommands {
	url, ca := s.agentURL(), s.ca.Fingerprint()
	return installCommands{
		Windows: fmt.Sprintf(`msiexec /i BerOps-Agent-x64.msi /qn SERVER="%s" REGKEY="%s" CAHASH="%s"`, url, secret, ca),
		MacOS: fmt.Sprintf(`sudo installer -pkg BerOps-Agent.pkg -target / && sudo /usr/local/bin/berops-agent configure -server "%s" -key "%s" -ca-hash "%s"`,
			url, secret, ca),
	}
}

func (s *Server) handleRevokeRegKey(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kayıt anahtarı bulunamadı")
		return
	}
	key, err := s.store.RevokeRegistrationKey(r.Context(), id, s.now())
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kayıt anahtarı bulunamadı veya zaten iptal edilmiş")
		return
	}
	if err != nil {
		s.log.Error("kayıt anahtarı iptal edilemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "regkey.revoke", TargetType: "registration_key", TargetID: key.ID, Result: store.ResultSuccess,
		SourceIP: clientIP(r),
	})
	writeJSON(w, http.StatusOK, key)
}

// onlineWindow, makinenin çevrimiçi sayılması için son heartbeat'in en fazla ne kadar eski olabileceğidir.
func (s *Server) onlineWindow() time.Duration {
	return 3 * time.Duration(s.cfg.Agent.HeartbeatSeconds) * time.Second
}

func (s *Server) handleSetMachineStatus(op string) authedHandler {
	return func(w http.ResponseWriter, r *http.Request, sess *store.Session) {
		id := r.PathValue("id")
		if !validUUID(id) {
			writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
			return
		}
		m, err := s.store.GetMachine(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, codeNotFound, "Makine bulunamadı")
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		var next string
		switch {
		case op == "approve" && m.Status == protocol.StatusPending:
			next = protocol.StatusActive
		case op == "reject" && (m.Status == protocol.StatusPending || m.Status == protocol.StatusActive):
			next = protocol.StatusRejected
		default:
			writeError(w, http.StatusConflict, codeConflict, fmt.Sprintf("Makine durumu (%s) bu işleme uygun değil", m.Status))
			return
		}
		m, err = s.store.SetMachineStatus(r.Context(), id, next)
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		s.audit(r.Context(), store.AuditEntry{
			ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
			Action: "machine." + op, TargetType: "machine", TargetID: m.ID, Result: store.ResultSuccess,
			SourceIP: clientIP(r), Params: map[string]any{"hostname": m.Hostname},
		})
		writeJSON(w, http.StatusOK, m)
	}
}
