// Package tlspin, ajanın sunucuyu önceden dağıtılmış bir CA dosyası olmadan, yalnızca
// CA parmak iziyle (pin) doğrulamasını sağlar.
package tlspin

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Fingerprint, sertifikanın "sha256:<hex>" biçimindeki parmak izidir.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Normalize, kullanıcıdan gelen parmak izini karşılaştırılabilir biçime getirir.
func Normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.ReplaceAll(s, ":", "")
	return "sha256:" + s
}

// Config, pin'lenmiş CA'ya göre sunucuyu doğrulayan bir TLS istemci yapılandırması döner.
//
// Standart doğrulama kapatılır (InsecureSkipVerify) ve yerine VerifyConnection kullanılır:
// sunucunun sunduğu zincirde parmak izi pin ile eşleşen bir CA aranır, sonra sunucu
// sertifikası o CA'ya ve ana makine adına göre tam olarak doğrulanır. Pin eşleşmezse
// el sıkışma başarısız olur; yani doğrulama atlanmış olmaz, yalnızca güven kökü pin'den gelir.
func Config(pin string, serverName string) (*tls.Config, error) {
	if strings.TrimSpace(pin) == "" {
		return nil, errors.New("CA parmak izi (CAHASH) gerekli")
	}
	want := Normalize(pin)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // doğrulama VerifyConnection içinde pin ile yapılıyor
		VerifyConnection: func(cs tls.ConnectionState) error {
			return VerifyChain(cs.PeerCertificates, want, cs.ServerName)
		},
	}, nil
}

// VerifyChain, sunulan zincirdeki pin'lenmiş CA'yı bulur ve sunucu sertifikasını doğrular.
func VerifyChain(peer []*x509.Certificate, pin, serverName string) error {
	if len(peer) == 0 {
		return errors.New("sunucu sertifika sunmadı")
	}
	want := Normalize(pin)
	var root *x509.Certificate
	for _, c := range peer {
		if c.IsCA && Fingerprint(c) == want {
			root = c
			break
		}
	}
	if root == nil {
		return fmt.Errorf("sunucunun CA'sı beklenen parmak iziyle (%s) eşleşmiyor", want)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := peer[0].Verify(x509.VerifyOptions{
		Roots:     roots,
		DNSName:   serverName,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("sunucu sertifikası doğrulanamadı: %w", err)
	}
	return nil
}
