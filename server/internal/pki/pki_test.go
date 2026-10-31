package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func newCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestLoadOrCreateCA_PersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreateCA(dir, "Test CA")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("CA anahtarı izni 0600 olmalı, %o bulundu", perm)
	}

	ca2, err := LoadOrCreateCA(dir, "Test CA")
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Fingerprint() != ca2.Fingerprint() {
		t.Error("yeniden yüklenen CA aynı parmak izine sahip olmalı")
	}
	if !ca2.Cert.IsCA {
		t.Error("CA sertifikası IsCA olmalı")
	}
}

func TestLoadOrCreateCA_MissingKeyIsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreateCA(dir, "Test CA"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, caKeyFile)); err != nil {
		t.Fatal(err)
	}
	// Anahtarı kaybolmuş bir CA'nın üzerine sessizce yenisini yazmak tüm ajanları koparır.
	if _, err := LoadOrCreateCA(dir, "Test CA"); err == nil {
		t.Fatal("anahtar eksikken hata beklenirdi")
	}
}

func TestIssueServerCert_VerifiesAgainstCA(t *testing.T) {
	ca, err := NewInMemoryCA("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	tc, err := ca.IssueServerCert([]string{"ber.example.test", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Certificate) != 2 {
		t.Fatalf("zincirde sunucu sertifikası ve CA olmalı, %d bulundu", len(tc.Certificate))
	}
	opts := x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	for _, host := range []string{"ber.example.test", "127.0.0.1"} {
		opts.DNSName = host
		if _, err := tc.Leaf.Verify(opts); err != nil {
			t.Errorf("%s için doğrulama başarısız: %v", host, err)
		}
	}
	opts.DNSName = "baska.example.test"
	if _, err := tc.Leaf.Verify(opts); err == nil {
		t.Error("listede olmayan ana makine adı reddedilmeliydi")
	}
}

func TestSignAgentCSR_OverridesSubjectAndSetsClientAuth(t *testing.T) {
	ca, err := NewInMemoryCA("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	const agentID = "7d0c8f4e-1111-4222-8333-944455556666"
	ac, err := ca.SignAgentCSR(newCSR(t, "admin"), agentID, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(ac.PEM)
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != agentID {
		t.Errorf("CN ajan ID olmalı; %q bulundu", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("ajan sertifikası istemci kimlik doğrulaması için geçerli olmalı: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("ajan sertifikası sunucu sertifikası olarak kullanılamamalı")
	}
	if ac.Serial == "" || !strings.HasPrefix(ac.Fingerprint, "sha256:") {
		t.Errorf("seri/parmak izi eksik: %+v", ac)
	}
}

func TestSignAgentCSR_RejectsTamperedCSR(t *testing.T) {
	ca, err := NewInMemoryCA("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := newCSR(t, "x")
	b, _ := pem.Decode(csrPEM)
	b.Bytes[len(b.Bytes)-1] ^= 0xff // imzayı boz
	if _, err := ca.SignAgentCSR(pem.EncodeToMemory(b), "id", time.Hour); err == nil {
		t.Fatal("bozuk CSR reddedilmeliydi")
	}
	if _, err := ca.SignAgentCSR([]byte("rastgele metin"), "id", time.Hour); err == nil {
		t.Fatal("PEM olmayan girdi reddedilmeliydi")
	}
}

func TestSignAgentCSR_RejectsUnsupportedKey(t *testing.T) {
	ca, err := NewInMemoryCA("Test CA")
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	if _, err := ca.SignAgentCSR(csrPEM, "id", time.Hour); err == nil {
		t.Fatal("RSA anahtarlı CSR reddedilmeliydi")
	}
}

func TestSigningKeyPersists(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrCreateSigningKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrCreateSigningKey(dir)
	if err != nil || !k1.Equal(k2) {
		t.Fatalf("anahtar yeniden yüklenince aynı olmalı: %v", err)
	}
	if st, _ := os.Stat(filepath.Join(dir, signingKeyFile)); st.Mode().Perm() != 0o600 && runtime.GOOS != "windows" {
		t.Errorf("anahtar izinleri %v", st.Mode().Perm())
	}
}
