// Package pki, sunucunun iç sertifika otoritesini (CA) yönetir: CA üretimi/yüklenmesi,
// ajan API'si için sunucu sertifikası ve ajan CSR'larının imzalanması.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/tlspin"
)

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"

	caValidity = 10 * 365 * 24 * time.Hour
	// Saat kaymalarına karşı sertifikalar biraz geçmişten başlatılır.
	backdate = 5 * time.Minute
)

// CA, imzalama yeteneği olan iç sertifika otoritesidir.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	key     *ecdsa.PrivateKey
	now     func() time.Time
}

// LoadOrCreateCA, dir içindeki CA'yı yükler; yoksa yenisini üretip kaydeder.
func LoadOrCreateCA(dir, commonName string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)

	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	switch {
	case certErr == nil && keyErr == nil:
		return parseCA(certPEM, keyPEM)
	case errors.Is(certErr, os.ErrNotExist) && errors.Is(keyErr, os.ErrNotExist):
		// İlk açılış: yeni CA üret.
	case certErr != nil:
		return nil, fmt.Errorf("CA sertifikası okunamadı: %w", certErr)
	default:
		return nil, fmt.Errorf("CA anahtarı okunamadı: %w", keyErr)
	}

	ca, keyPEM, err := newCA(commonName, time.Now)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("PKI dizini oluşturulamadı: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("CA anahtarı yazılamadı: %w", err)
	}
	if err := os.WriteFile(certPath, ca.CertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("CA sertifikası yazılamadı: %w", err)
	}
	return ca, nil
}

// NewInMemoryCA, diske yazmadan CA üretir (testler ve simülatör için).
func NewInMemoryCA(commonName string) (*CA, error) {
	ca, _, err := newCA(commonName, time.Now)
	return ca, err
}

func newCA(commonName string, now func() time.Time) (*CA, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("CA anahtarı üretilemedi: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	start := now().Add(-backdate)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Automation BER"}},
		NotBefore:             start,
		NotAfter:              start.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("CA sertifikası oluşturulamadı: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	ca := &CA{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
		now:     now,
	}
	return ca, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

func parseCA(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, errors.New("CA sertifikası PEM biçiminde değil")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA sertifikası ayrıştırılamadı: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, errors.New("CA anahtarı PEM biçiminde değil")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CA anahtarı ayrıştırılamadı: %w", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("CA anahtarı sertifikayla eşleşmiyor")
	}
	return &CA{Cert: cert, CertPEM: certPEM, key: key, now: time.Now}, nil
}

// Fingerprint, CA sertifikasının "sha256:<hex>" biçimindeki parmak izidir.
// Ajan kurulumunda CAHASH parametresi olarak kullanılır.
func (ca *CA) Fingerprint() string {
	return CertFingerprint(ca.Cert)
}

// CertFingerprint, bir sertifikanın DER kodlamasının SHA-256 parmak izidir.
func CertFingerprint(cert *x509.Certificate) string {
	return tlspin.Fingerprint(cert)
}

// Pool, yalnızca bu CA'yı içeren sertifika havuzudur.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// IssueServerCert, verilen DNS adları / IP adresleri için sunucu sertifikası üretir.
// Dönen tls.Certificate zincirinde CA da bulunur; ajanlar CA parmak izini bu zincirden doğrular.
func (ca *CA) IssueServerCert(hosts []string, validity time.Duration) (tls.Certificate, error) {
	if len(hosts) == 0 {
		return tls.Certificate{}, errors.New("sunucu sertifikası için en az bir ana makine adı gerekli")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	start := ca.now().Add(-backdate)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hosts[0], Organization: []string{"Automation BER"}},
		NotBefore:    start,
		NotAfter:     start.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sunucu sertifikası imzalanamadı: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der, ca.Cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}

// AgentCert, imzalanmış ajan sertifikasının özetidir.
type AgentCert struct {
	PEM         []byte
	Serial      string
	Fingerprint string
	NotAfter    time.Time
}

// SignAgentCSR, ajanın CSR'ını imzalar. CSR'daki konu bilgisi yok sayılır; CN her zaman
// sunucunun atadığı ajan ID'sidir, böylece ajan kendine başka bir kimlik seçemez.
func (ca *CA) SignAgentCSR(csrPEM []byte, agentID string, validity time.Duration) (*AgentCert, error) {
	b, _ := pem.Decode(csrPEM)
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR PEM biçiminde değil")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR ayrıştırılamadı: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR imzası geçersiz: %w", err)
	}
	if err := checkAgentKey(csr.PublicKey); err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	start := ca.now().Add(-backdate)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, OrganizationalUnit: []string{"BER Agent"}},
		NotBefore:    start,
		NotAfter:     start.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("ajan sertifikası imzalanamadı: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &AgentCert{
		PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		Serial:      SerialString(cert),
		Fingerprint: CertFingerprint(cert),
		NotAfter:    cert.NotAfter,
	}, nil
}

// checkAgentKey, zayıf anahtarlarla kayıt yapılmasını engeller.
func checkAgentKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return errors.New("ECDSA anahtarı en az P-256 olmalı")
		}
		return nil
	default:
		return fmt.Errorf("desteklenmeyen ajan anahtar türü: %T", pub)
	}
}

// SerialString, sertifika seri numarasının onaltılık gösterimidir.
func SerialString(cert *x509.Certificate) string {
	return cert.SerialNumber.Text(16)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("seri numarası üretilemedi: %w", err)
	}
	return n, nil
}
