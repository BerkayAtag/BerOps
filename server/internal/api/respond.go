package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// Hata kodları. Konsol bunları "errors.<kod>" çeviri anahtarına eşler.
const (
	codeInvalidCredentials = "auth.invalid_credentials"
	codeRateLimited        = "auth.rate_limited"
	codeUnauthenticated    = "auth.unauthenticated"
	codeForbidden          = "auth.forbidden"
	codeCSRF               = "auth.csrf"
	codeInvalidRequest     = "request.invalid"
	codeUnsupportedMedia   = "request.unsupported_media_type"
	codeNotFound           = "not_found"
	codeConflict           = "conflict"
	codeInternal           = "internal"
	codeEnrollInvalidKey   = "enroll.invalid_key"
	codeEnrollInvalidCSR   = "enroll.invalid_csr"
	codeAgentUnknown       = "agent.unknown"
	codeAgentRevoked       = "agent.revoked"
	// codeDirectoryUnavailable, AD'ye ulaşılamadığında döner; konsol kurtarma hesabını önerir.
	codeDirectoryUnavailable = "auth.directory_unavailable"
	codeNoRoleMapping        = "auth.no_role_mapping"
)

const maxJSONBody = 1 << 20 // 1 MiB

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, protocol.ErrorResponse{Code: code, Message: msg})
}

// decodeJSON, gövdeyi boyut sınırı ve bilinmeyen alan kontrolüyle çözer. JSON dışındaki
// içerik türlerini reddetmek, tarayıcı formlarıyla yapılan CSRF saldırılarını da engeller.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, codeUnsupportedMedia, "İçerik türü application/json olmalı")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, codeInvalidRequest, "İstek gövdesi çok büyük")
			return false
		}
		writeError(w, http.StatusBadRequest, codeInvalidRequest, "İstek gövdesi geçersiz: "+err.Error())
		return false
	}
	return true
}

// clientIP, isteğin kaynak IP'sidir. Ters vekil başlıkları (X-Forwarded-For) varsayılan
// olarak güvenilmez kabul edilir; sahte IP ile hız sınırının aşılmasını önler.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// newUUID, rastgele (sürüm 4) UUID üretir.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// validUUID, metnin kanonik UUID biçiminde olup olmadığını denetler. Geçersiz kimlikler
// veritabanına gönderilmeden 404 ile reddedilir.
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}
