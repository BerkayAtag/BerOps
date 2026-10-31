package api

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
)

// SessionCookie, oturum çerezinin adıdır. "__Host-" öneki çerezin yalnızca HTTPS üzerinden,
// Domain olmadan ve Path=/ ile ayarlanabilmesini tarayıcı düzeyinde zorunlu kılar.
const SessionCookie = "__Host-ber_session"

// CSRFHeader, durum değiştiren isteklerde oturumun CSRF token'ını taşıyan başlıktır.
const CSRFHeader = "X-CSRF-Token"

// Oturum son etkinlik zamanı en fazla bu sıklıkta yazılır (her istekte UPDATE yapmamak için).
const sessionTouchInterval = time.Minute

type middleware func(http.Handler) http.Handler

func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// securityHeaders, konsol yanıtlarına güvenlik başlıklarını ekler.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; "+
			"base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.log.Debug("istek", "yöntem", r.Method, "yol", r.URL.Path, "durum", rec.status,
			"süre_ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("işleyici panikledi", "hata", v, "yol", r.URL.Path, "yığın", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type sessionKey struct{}

func sessionFrom(ctx context.Context) *store.Session {
	s, _ := ctx.Value(sessionKey{}).(*store.Session)
	return s
}

type authedHandler func(w http.ResponseWriter, r *http.Request, sess *store.Session)

// authed; oturumu doğrular, durum değiştiren isteklerde CSRF token'ını denetler ve
// perm boş değilse kullanıcının rolünün bu izne sahip olduğunu sunucu tarafında zorunlu kılar.
func (s *Server) authed(perm auth.Permission, h authedHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.loadSession(w, r)
		if !ok {
			return
		}
		if !isSafeMethod(r.Method) {
			got := r.Header.Get(CSRFHeader)
			if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRFToken)) != 1 {
				writeError(w, http.StatusForbidden, codeCSRF, "CSRF doğrulaması başarısız")
				return
			}
		}
		if perm != "" && !auth.HasPermission(auth.Role(sess.User.Role), perm) {
			s.audit(r.Context(), store.AuditEntry{
				ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username,
				Action: "authz.denied", Result: store.ResultDenied, SourceIP: clientIP(r),
				Params: map[string]any{"method": r.Method, "path": r.URL.Path, "permission": string(perm)},
			})
			writeError(w, http.StatusForbidden, codeForbidden, "Bu işlem için yetkiniz yok")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)), sess)
	})
}

func (s *Server) loadSession(w http.ResponseWriter, r *http.Request) (*store.Session, bool) {
	c, err := r.Cookie(SessionCookie)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Oturum açmanız gerekiyor")
		return nil, false
	}
	hash := auth.HashToken(c.Value)
	sess, err := s.store.GetSession(r.Context(), hash)
	if errors.Is(err, store.ErrNotFound) {
		clearSessionCookie(w)
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Oturum geçersiz")
		return nil, false
	}
	if err != nil {
		s.log.Error("oturum okunamadı", "hata", err)
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return nil, false
	}
	now := s.now()
	if !now.Before(sess.ExpiresAt) || now.Sub(sess.LastSeenAt) >= s.cfg.Session.IdleTimeout.D() || sess.User.Disabled {
		_ = s.store.DeleteSession(r.Context(), hash)
		clearSessionCookie(w)
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Oturum süresi doldu")
		return nil, false
	}
	if now.Sub(sess.LastSeenAt) >= sessionTouchInterval {
		if err := s.store.TouchSession(r.Context(), hash, now); err != nil {
			s.log.Warn("oturum güncellenemedi", "hata", err)
		}
	}
	return sess, true
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}
