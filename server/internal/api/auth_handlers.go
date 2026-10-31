package api

import (
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type meUser struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
	Source      string `json:"source"`
}

type meResponse struct {
	User        meUser            `json:"user"`
	Permissions []auth.Permission `json:"permissions"`
	CSRFToken   string            `json:"csrf_token"`
}

func newMeResponse(u store.User, csrf string) meResponse {
	return meResponse{
		User: meUser{
			ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Role: u.Role, Source: u.Source,
		},
		Permissions: auth.PermissionsOf(auth.Role(u.Role)),
		CSRFToken:   csrf,
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req, 8<<10) {
		return
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "Kullanıcı adı ve parola gerekli")
		return
	}
	ip := clientIP(r)
	ipKey := "ip:" + ip
	userKey := "user:" + strings.ToLower(req.Username)

	for _, key := range []string{ipKey, userKey} {
		if ok, wait := s.loginLimiter.Allowed(key); !ok {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			s.audit(r.Context(), store.AuditEntry{
				ActorType: store.ActorUser, ActorName: req.Username, Action: "auth.login",
				Result: store.ResultDenied, Detail: "hız sınırı", SourceIP: ip,
			})
			writeError(w, http.StatusTooManyRequests, codeRateLimited,
				fmt.Sprintf("Çok fazla başarısız deneme. %d saniye sonra tekrar deneyin.", secs))
			return
		}
	}

	fail := func(detail string) {
		s.loginLimiter.Fail(ipKey)
		s.loginLimiter.Fail(userKey)
		s.audit(r.Context(), store.AuditEntry{
			ActorType: store.ActorUser, ActorName: req.Username, Action: "auth.login",
			Result: store.ResultFailure, Detail: detail, SourceIP: ip,
		})
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "Kullanıcı adı veya parola hatalı")
	}

	user, err := s.store.GetUserByUsername(r.Context(), req.Username)
	switch {
	case errors.Is(err, store.ErrNotFound):
		_ = auth.VerifyPassword(s.dummyHash, req.Password)
		fail("kullanıcı yok")
		return
	case err != nil:
		s.log.Error("kullanıcı okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// AD kullanıcıları Aşama 5'te LDAPS ile doğrulanacak; o zamana kadar yalnızca yerel hesaplar.
	if user.Source != "local" || user.PasswordHash == "" {
		_ = auth.VerifyPassword(s.dummyHash, req.Password)
		fail("yerel olmayan hesap")
		return
	}
	if err := auth.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		fail("hatalı parola")
		return
	}
	if user.Disabled {
		fail("hesap devre dışı")
		return
	}

	token, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	csrf, err := auth.NewToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	now := s.now()
	expires := now.Add(s.cfg.Session.AbsoluteTimeout.D())
	if err := s.store.CreateSession(r.Context(), auth.HashToken(token), user.ID, csrf, expires, ip, r.UserAgent()); err != nil {
		s.log.Error("oturum oluşturulamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.loginLimiter.Reset(userKey)
	if err := s.store.TouchLastLogin(r.Context(), user.ID, now); err != nil {
		s.log.Warn("son giriş zamanı yazılamadı", "hata", err)
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: user.ID, ActorName: user.Username, Action: "auth.login",
		Result: store.ResultSuccess, SourceIP: ip,
	})
	setSessionCookie(w, token, expires)
	writeJSON(w, http.StatusOK, newMeResponse(*user, csrf))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	if err := s.store.DeleteSession(r.Context(), sess.TokenHash); err != nil {
		s.log.Error("oturum silinemedi", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "auth.logout",
		Result: store.ResultSuccess, SourceIP: clientIP(r),
	})
	clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, _ *http.Request, sess *store.Session) {
	writeJSON(w, http.StatusOK, newMeResponse(sess.User, sess.CSRFToken))
}
