package api

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

// minPasswordLen, yerel hesap parolalarının en kısa uzunluğudur.
const minPasswordLen = 12

type userResponse struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Email       string     `json:"email"`
	Source      string     `json:"source"`
	Role        string     `json:"role"`
	IsRecovery  bool       `json:"is_recovery"`
	Disabled    bool       `json:"disabled"`
	ScopeOUs    []string   `json:"scope_ous"`
	ADDN        string     `json:"ad_dn"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

func toUserResponse(u store.User) userResponse {
	scope := u.ScopeOUs
	if scope == nil {
		scope = []string{}
	}
	return userResponse{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Email: u.Email, Source: u.Source,
		Role: u.Role, IsRecovery: u.IsRecovery, Disabled: u.Disabled, ScopeOUs: scope, ADDN: u.ADDN,
		CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt}
}

func validPassword(p string) error {
	if utf8.RuneCountInString(p) < minPasswordLen {
		return errors.New("parola en az 12 karakter olmalı")
	}
	if len(p) > 256 {
		return errors.New("parola çok uzun")
	}
	return nil
}

func cleanScope(in []string) ([]string, error) {
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(strings.ToUpper(s), "DC=") || len(s) > 500 {
			return nil, errors.New("kapsam OU'ları tam DN olmalı (ör. OU=İzmir,OU=Şubeler,DC=corp,DC=example)")
		}
		out = append(out, s)
	}
	if len(out) > 50 {
		return nil, errors.New("en fazla 50 OU")
	}
	return out, nil
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	out := make([]userResponse, len(users))
	for i, u := range users {
		out[i] = toUserResponse(u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

type createUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"display_name"`
	Password    string   `json:"password"`
	Role        string   `json:"role"`
	ScopeOUs    []string `json:"scope_ous"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req createUserRequest
	if !decodeJSON(w, r, &req, 16<<10) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || len(req.Username) > 100 || strings.ContainsAny(req.Username, `\@ `) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kullanıcı adı 1-100 karakter olmalı; \\, @ ve boşluk içeremez")
		return
	}
	if !auth.ValidRole(auth.Role(req.Role)) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz rol")
		return
	}
	if err := validPassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	scope, err := cleanScope(req.ScopeOUs)
	if err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	u, err := s.store.CreateLocalUser(r.Context(), req.Username, strings.TrimSpace(req.DisplayName), hash, req.Role, false)
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, codeConflict, "Bu kullanıcı adı zaten var")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if len(scope) > 0 {
		if u, err = s.store.UpdateUser(r.Context(), u.ID, store.UserUpdate{ScopeOUs: &scope}); err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "user.create",
		TargetType: "user", TargetID: u.ID, Result: store.ResultSuccess, SourceIP: clientIP(r),
		Params: map[string]any{"username": u.Username, "role": u.Role, "scope_ous": scope},
	})
	writeJSON(w, http.StatusCreated, toUserResponse(*u))
}

type updateUserRequest struct {
	DisplayName *string   `json:"display_name"`
	Role        *string   `json:"role"`
	Disabled    *bool     `json:"disabled"`
	ScopeOUs    *[]string `json:"scope_ous"`
	Password    *string   `json:"password"`
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kullanıcı bulunamadı")
		return
	}
	var req updateUserRequest
	if !decodeJSON(w, r, &req, 16<<10) {
		return
	}
	u, err := s.store.GetUser(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Kullanıcı bulunamadı")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	upd := store.UserUpdate{DisplayName: req.DisplayName, Disabled: req.Disabled}
	if req.Role != nil {
		if !auth.ValidRole(auth.Role(*req.Role)) {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "Geçersiz rol")
			return
		}
		if u.Source == "ad" {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "AD kullanıcılarının rolü grup eşlemelerinden belirlenir")
			return
		}
		upd.Role = req.Role
	}
	if req.ScopeOUs != nil {
		if u.Source == "ad" {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "AD kullanıcılarının kapsamı grup eşlemelerinden belirlenir")
			return
		}
		scope, err := cleanScope(*req.ScopeOUs)
		if err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
			return
		}
		upd.ScopeOUs = &scope
	}
	if req.Password != nil {
		if u.Source != "local" {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, "AD kullanıcılarının parolası AD'de değiştirilir")
			return
		}
		if err := validPassword(*req.Password); err != nil {
			writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
			return
		}
		h, err := auth.HashPassword(*req.Password)
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		upd.PasswordHash = &h
	}
	// Kendini kilitlemeye ve son yöneticiyi kaldırmaya karşı koruma.
	demote := req.Role != nil && *req.Role != "admin"
	disable := req.Disabled != nil && *req.Disabled
	if id == sess.User.ID && (demote || disable) {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kendi hesabınızı devre dışı bırakamaz veya rolünüzü düşüremezsiniz")
		return
	}
	if u.Role == "admin" && !u.Disabled && (demote || disable) {
		n, err := s.store.CountActiveAdmins(r.Context(), u.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			return
		}
		if n == 0 {
			writeError(w, http.StatusConflict, codeConflict, "Son etkin yönetici kaldırılamaz")
			return
		}
	}
	nu, err := s.store.UpdateUser(r.Context(), id, upd)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// Rol, kapsam, durum veya parola değiştiyse açık oturumlar kapatılır.
	if req.Role != nil || req.ScopeOUs != nil || disable || req.Password != nil {
		if err := s.store.DeleteUserSessions(r.Context(), id); err != nil {
			s.log.Warn("kullanıcı oturumları kapatılamadı", "hata", err)
		}
	}
	params := map[string]any{"username": u.Username}
	if req.Role != nil {
		params["role"] = map[string]string{"old": u.Role, "new": *req.Role}
	}
	if req.Disabled != nil {
		params["disabled"] = *req.Disabled
	}
	if upd.ScopeOUs != nil {
		params["scope_ous"] = *upd.ScopeOUs
	}
	if req.Password != nil {
		params["password_reset"] = true
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "user.update",
		TargetType: "user", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r), Params: params,
	})
	writeJSON(w, http.StatusOK, toUserResponse(*nu))
}

type changePasswordRequest struct {
	Current string `json:"current_password"`
	New     string `json:"new_password"`
}

// handleChangePassword, yerel kullanıcının kendi parolasını değiştirmesidir. Diğer oturumlar kapatılır.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	var req changePasswordRequest
	if !decodeJSON(w, r, &req, 4<<10) {
		return
	}
	u, err := s.store.GetUser(r.Context(), sess.User.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if u.Source != "local" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "AD kullanıcılarının parolası AD'de değiştirilir")
		return
	}
	if auth.VerifyPassword(u.PasswordHash, req.Current) != nil {
		s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: u.ID, ActorName: u.Username,
			Action: "auth.password_change", Result: store.ResultFailure, Detail: "mevcut parola hatalı", SourceIP: clientIP(r)})
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Mevcut parola hatalı")
		return
	}
	if err := validPassword(req.New); err != nil {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	h, err := auth.HashPassword(req.New)
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	if _, err := s.store.UpdateUser(r.Context(), u.ID, store.UserUpdate{PasswordHash: &h}); err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// Bu oturum dışındakiler kapatılır; yeni oturum açmak gerekmez.
	if err := s.store.DeleteUserSessions(r.Context(), u.ID); err == nil {
		_ = s.store.CreateSession(r.Context(), sess.TokenHash, u.ID, sess.CSRFToken, s.now(), sess.ExpiresAt, clientIP(r), r.UserAgent())
	}
	s.audit(r.Context(), store.AuditEntry{ActorType: store.ActorUser, ActorID: u.ID, ActorName: u.Username,
		Action: "auth.password_change", Result: store.ResultSuccess, SourceIP: clientIP(r)})
	w.WriteHeader(http.StatusNoContent)
}
