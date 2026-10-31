package api

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/pki"
	"github.com/BerkayAtag/BerOps/server/internal/store"
)

// Relay ile sunucu arasındaki başlıklar.
const (
	// HeaderAgentCert, relay'in doğruladığı ajan sertifikasıdır (base64 DER). Sunucu bu başlığı
	// yalnızca relay sertifikasıyla gelen isteklerde dikkate alır.
	HeaderAgentCert = "X-Ber-Agent-Cert"
	// HeaderAgentIP, ajanın relay'e bağlandığı IP adresidir.
	HeaderAgentIP = "X-Ber-Agent-Ip"
	// HeaderRelayProbe, relay'in paket indirme isteğini yalnızca yetki ve meta veri için
	// sorduğunu belirtir; sunucu gövde göndermez.
	HeaderRelayProbe = "X-Ber-Relay-Probe"
	// HeaderSHA256, paket dosyasının özetidir (yoklama yanıtında).
	HeaderSHA256 = "X-Ber-Sha256"
)

// agentViaRelay, relay sertifikasını kayıtla doğrular ve iletilen ajan sertifikasını CA'ya
// karşı doğrulayıp döner.
func (s *Server) agentViaRelay(w http.ResponseWriter, r *http.Request, relayCert *x509.Certificate) (*x509.Certificate, bool) {
	rl, err := s.store.GetRelay(r.Context(), strings.TrimPrefix(relayCert.Subject.CommonName, pki.RelayPrefix))
	if err != nil || rl.RevokedAt != nil || rl.CertSerial != pki.SerialString(relayCert) {
		writeError(w, http.StatusUnauthorized, codeAgentRevoked, "Relay tanınmıyor veya iptal edilmiş")
		return nil, false
	}
	if err := s.store.TouchRelay(r.Context(), rl.ID, clientIP(r), s.now()); err != nil {
		s.log.Warn("relay son görülme zamanı yazılamadı", "hata", err)
	}
	der, err := base64.StdEncoding.DecodeString(r.Header.Get(HeaderAgentCert))
	if err != nil || len(der) == 0 {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Relay ajan sertifikasını iletmedi")
		return nil, false
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "İletilen ajan sertifikası geçersiz")
		return nil, false
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: s.ca.Pool(), CurrentTime: s.now(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "İletilen ajan sertifikası doğrulanamadı")
		return nil, false
	}
	if strings.HasPrefix(cert.Subject.CommonName, pki.RelayPrefix) {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Relay başka bir relay'i iletemez")
		return nil, false
	}
	return cert, true
}

// relayFromTLS, isteğin doğrudan bir relay'den (ajan iletmeden) geldiğini doğrular.
func (s *Server) relayFromTLS(w http.ResponseWriter, r *http.Request) (*store.Relay, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "Relay sertifikası gerekli")
		return nil, false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	if !strings.HasPrefix(leaf.Subject.CommonName, pki.RelayPrefix) {
		writeError(w, http.StatusForbidden, codeForbidden, "Bu uç nokta yalnızca relay'ler içindir")
		return nil, false
	}
	rl, err := s.store.GetRelay(r.Context(), strings.TrimPrefix(leaf.Subject.CommonName, pki.RelayPrefix))
	if err != nil || rl.RevokedAt != nil || rl.CertSerial != pki.SerialString(leaf) {
		writeError(w, http.StatusUnauthorized, codeAgentRevoked, "Relay tanınmıyor veya iptal edilmiş")
		return nil, false
	}
	return rl, true
}

// handleRelayFile, relay'in önbelleğine paket dosyasını özetle çekmesidir. Yalnızca
// kütüphanede veya açık bir aksiyonda bulunan dosyalar verilir; relay–sunucu bağlantısına
// istemci hız sınırı uygulanmaz.
func (s *Server) handleRelayFile(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.relayFromTLS(w, r); !ok {
		return
	}
	sha := r.PathValue("sha")
	if !sha256Hex.MatchString(sha) {
		writeError(w, http.StatusNotFound, codeNotFound, "Dosya bulunamadı")
		return
	}
	if ok, err := s.store.PackageFileKnown(r.Context(), sha); err != nil || !ok {
		writeError(w, http.StatusNotFound, codeNotFound, "Dosya bulunamadı")
		return
	}
	f, err := os.Open(s.packagePath(sha))
	if err != nil {
		writeError(w, http.StatusNotFound, codeNotFound, "Dosya bulunamadı")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	noWriteDeadline(w)
	fileDownloadHeaders(w, "application/octet-stream")
	http.ServeContent(w, r, sha, info.ModTime(), f)
}

// isRelayRequest, isteğin bir relay üzerinden geldiğini döner.
func isRelayRequest(r *http.Request) bool {
	return r.TLS != nil && len(r.TLS.VerifiedChains) > 0 &&
		strings.HasPrefix(r.TLS.VerifiedChains[0][0].Subject.CommonName, pki.RelayPrefix)
}

// relayProbeResponse, relay'in yoklamasına yetki ve meta veriyi gövdesiz döner.
func relayProbeResponse(w http.ResponseWriter, sha string, size int64, kbps int) {
	h := w.Header()
	h.Set(HeaderSHA256, sha)
	h.Set("X-Ber-Size", strconv.FormatInt(size, 10))
	h.Set("X-Ber-Rate-Kbps", strconv.Itoa(kbps))
	w.WriteHeader(http.StatusNoContent)
}

// --- Konsol ---

func (s *Server) handleListRelays(w http.ResponseWriter, r *http.Request, _ *store.Session) {
	items, err := s.store.ListRelays(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	// Son beş dakika içinde istek ileten relay çevrimiçi sayılır.
	type item struct {
		store.Relay
		Online bool `json:"online"`
	}
	out := make([]item, len(items))
	for i, rl := range items {
		out[i] = item{rl, rl.RevokedAt == nil && rl.LastSeenAt != nil && s.now().Sub(*rl.LastSeenAt) < 5*time.Minute}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleRevokeRelay(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	id := r.PathValue("id")
	if !validUUID(id) {
		writeError(w, http.StatusNotFound, codeNotFound, "Relay bulunamadı")
		return
	}
	if err := s.store.RevokeRelay(r.Context(), id, s.now()); errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, codeNotFound, "Relay bulunamadı veya zaten iptal edilmiş")
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, codeInternal, "Sunucu hatası")
		return
	}
	s.audit(r.Context(), store.AuditEntry{
		ActorType: store.ActorUser, ActorID: sess.User.ID, ActorName: sess.User.Username, Action: "relay.revoke",
		TargetType: "relay", TargetID: id, Result: store.ResultSuccess, SourceIP: clientIP(r),
	})
	w.WriteHeader(http.StatusNoContent)
}
