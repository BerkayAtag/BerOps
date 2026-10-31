// Package identity, ajanın kriptografik kimliğini (özel anahtar, sertifika, CA) ve
// kayıt durumunu veri dizininde saklar.
package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

const (
	keyFile   = "agent.key"
	certFile  = "agent.crt"
	caFile    = "ca.crt"
	stateFile = "state.json"
)

// ErrNotEnrolled, ajan henüz kaydolmamışsa döner.
var ErrNotEnrolled = errors.New("ajan henüz kaydolmamış")

// State, kayıt sonrası kalıcı durumdur.
type State struct {
	AgentID    string    `json:"agent_id"`
	Status     string    `json:"status"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// Store, kimlik dosyalarının bulunduğu dizindir.
type Store struct {
	Dir string
}

func (s Store) path(name string) string { return filepath.Join(s.Dir, name) }

// LoadOrCreateKey, ajanın özel anahtarını yükler; yoksa üretir. Anahtar makineden hiç çıkmaz;
// sunucuya yalnızca CSR gönderilir.
func (s Store) LoadOrCreateKey() (*ecdsa.PrivateKey, error) {
	b, err := os.ReadFile(s.path(keyFile))
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("ajan anahtarı PEM biçiminde değil")
		}
		return x509.ParseECPrivateKey(blk.Bytes)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	if err := writeAtomic(s.path(keyFile), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// NewCSR, anahtar için sertifika imzalama isteği üretir. Konu bilgisi boş bırakılır;
// sunucu CN'yi kendi atadığı ajan ID'siyle doldurur.
func NewCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// SaveEnrollment, kayıt yanıtındaki sertifikaları ve durumu kaydeder.
func (s Store) SaveEnrollment(resp *protocol.EnrollResponse, at time.Time) error {
	if blk, _ := pem.Decode([]byte(resp.CertificatePEM)); blk == nil {
		return errors.New("sunucudan gelen sertifika PEM biçiminde değil")
	}
	if err := writeAtomic(s.path(certFile), []byte(resp.CertificatePEM), 0o644); err != nil {
		return err
	}
	if err := writeAtomic(s.path(caFile), []byte(resp.CACertificatePEM), 0o644); err != nil {
		return err
	}
	b, err := json.MarshalIndent(State{AgentID: resp.AgentID, Status: resp.Status, EnrolledAt: at}, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(s.path(stateFile), b, 0o600)
}

// Load, kayıtlı kimliği ve mTLS için istemci sertifikasını döner.
func (s Store) Load() (*State, *tls.Certificate, error) {
	b, err := os.ReadFile(s.path(stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, nil, fmt.Errorf("%s okunamadı: %w", stateFile, err)
	}
	cert, err := tls.LoadX509KeyPair(s.path(certFile), s.path(keyFile))
	if err != nil {
		return nil, nil, fmt.Errorf("ajan sertifikası yüklenemedi: %w", err)
	}
	return &st, &cert, nil
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
