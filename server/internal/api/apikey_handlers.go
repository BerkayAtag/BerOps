package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BerkayAtag/BerOps/server/internal/auth"
	"github.com/BerkayAtag/BerOps/server/internal/store"
)

type createAPIKeyRequest struct {
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	ScopeOUs      []string `json:"scope_ous"`
	ExpiresInDays int      `json:"expires_in_days"` // 0 = süresiz
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	keys, err := s.store.ListAPIKeys(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

// handleCreateAPIKey, yeni anahtar üretir; anahtarın kendisi yalnızca bu yanıtta döner.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createAPIKeyRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	switch {
	case req.Name == "" || utf8.RuneCountInString(req.Name) > 100:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Ad 1-100 karakter olmalı")
		return
	case !auth.ValidRole(auth.Role(req.Role)):
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Rol admin, technician veya readonly olmalı")
		return
	case req.ExpiresInDays < 0 || req.ExpiresInDays > 730:
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçerlilik 0-730 gün olmalı")
		return
	}
	scope, err := cleanScope(req.ScopeOUs)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		t := s.now().AddDate(0, 0, req.ExpiresInDays)
		expires = &t
	}
	secret, prefix, err := auth.NewAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	k, err := s.store.CreateAPIKey(r.Context(), req.Name, prefix, auth.HashToken(secret), req.Role, scope, sess.User.ID, expires)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "apikey.create", TargetType: "api_key", TargetID: k.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"name": k.Name, "role": k.Role, "scope_ous": k.ScopeOUs, "expires_at": k.ExpiresAt}})
	writeJSON(w, http.StatusCreated, map[string]any{"key": k, "secret": secret})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Anahtar bulunamadı")
		return
	}
	if err := s.store.RevokeAPIKey(r.Context(), id, s.now()); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Anahtar bulunamadı veya zaten iptal edilmiş")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
		Action: "apikey.revoke", TargetType: "api_key", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
