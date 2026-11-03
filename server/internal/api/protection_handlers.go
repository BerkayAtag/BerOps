package api

import (
	"crypto/rand"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// protectionCache, kaldırma korumasını heartbeat'ler için kısa süre tutar.
type protectionCache struct {
	mu      sync.Mutex
	value   protocol.UninstallProtection
	expires time.Time
}

// uninstallProtection, heartbeat yanıtına eklenecek kaldırma korumasını döner.
func (s *Server) uninstallProtection(r *http.Request) (*protocol.UninstallProtection, error) {
	s.protection.mu.Lock()
	defer s.protection.mu.Unlock()
	now := s.now()
	if now.After(s.protection.expires) {
		p, err := s.store.GetAgentProtection(r.Context())
		if err != nil {
			return nil, err
		}
		s.protection.value, s.protection.expires = p.UninstallProtection, now.Add(settingsCacheTTL)
	}
	v := s.protection.value
	return &v, nil
}

// minUninstallCode, kaldırma kodunun en kısa uzunluğudur. Özet her ajanda bulunduğundan kod,
// çevrimdışı tahmine karşı parola politikasıyla aynı uzunlukta tutulur.
const minUninstallCode = 12

type protectionResponse struct {
	Enabled   bool       `json:"enabled"`
	UpdatedAt *time.Time `json:"updated_at"`
}

func (s *Server) handleGetAgentProtection(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	p, err := s.store.GetAgentProtection(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, protectionResponse{Enabled: p.Enabled, UpdatedAt: p.UpdatedAt})
}

// handlePutAgentProtection, kaldırma korumasını açar, kodunu değiştirir veya kapatır. Kodun
// kendisi saklanmaz ve denetim kaydına yazılmaz.
func (s *Server) handlePutAgentProtection(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req struct {
		Enabled bool   `json:"enabled"`
		Code    string `json:"code"`
	}
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	cur, err := s.store.GetAgentProtection(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	next := protocol.UninstallProtection{Enabled: req.Enabled}
	codeChanged := false
	switch {
	case !req.Enabled:
	case req.Code == "" && cur.Enabled:
		next = cur.UninstallProtection // kod değişmeden açık kalır
	case req.Code == "":
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kaldırma kodu gerekli")
		return
	case strings.ContainsFunc(req.Code, func(r rune) bool { return r == '"' || unicode.IsControl(r) }):
		// Kod MSI komut satırına tırnak içinde eklenir.
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kaldırma kodu çift tırnak veya kontrol karakteri içeremez")
		return
	case strings.TrimSpace(req.Code) != req.Code || utf8.RuneCountInString(req.Code) < minUninstallCode || utf8.RuneCountInString(req.Code) > 128:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kaldırma kodu 12-128 karakter olmalı ve boşlukla başlayıp bitmemeli")
		return
	default:
		next.Salt = make([]byte, 16)
		if _, err := rand.Read(next.Salt); err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		next.Iterations = protocol.UninstallCodeIterations
		if next.Hash, err = protocol.HashUninstallCode(req.Code, next.Salt, next.Iterations); err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		codeChanged = true
	}
	now := s.now()
	if err := s.store.SaveAgentProtection(r.Context(), next, sess.User.ID, now); err != nil {
		s.log.Error("kaldırma koruması kaydedilemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.protection.mu.Lock()
	s.protection.expires = time.Time{}
	s.protection.mu.Unlock()
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "settings.agent_protection.update", TargetType: "settings", TargetID: "agent_protection",
		Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"old_enabled": cur.Enabled, "enabled": next.Enabled, "code_changed": codeChanged},
	})
	writeJSON(w, http.StatusOK, protectionResponse{Enabled: next.Enabled, UpdatedAt: &now})
}
