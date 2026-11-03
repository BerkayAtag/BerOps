package identity

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestKeyIsCreatedOnceWithPrivatePermissions(t *testing.T) {
	s := Store{Dir: filepath.Join(t.TempDir(), "agent")}
	k1, err := s.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := s.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !k1.Equal(k2) {
		t.Error("ikinci çağrı aynı anahtarı yüklemeli")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(s.Dir, keyFile))
		if info.Mode().Perm() != 0o600 {
			t.Errorf("anahtar izni 0600 olmalı: %o", info.Mode().Perm())
		}
	}
}

func TestEnrollmentRoundTrip(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if _, _, err := s.Load(); err != ErrNotEnrolled {
		t.Fatalf("kayıt öncesi ErrNotEnrolled beklenirdi: %v", err)
	}
	key, err := s.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := NewCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		t.Fatalf("CSR geçerli olmalı: %v", err)
	}

	// Sunucunun yapacağı imzalamanın yerine kendinden imzalı sertifika.
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "ajan-1"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err := s.SaveEnrollment(&protocol.EnrollResponse{
		AgentID: "ajan-1", Status: "active", CertificatePEM: certPEM, CACertificatePEM: certPEM,
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	st, cert, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if st.AgentID != "ajan-1" || st.Status != "active" || len(cert.Certificate) != 1 {
		t.Errorf("beklenmeyen kimlik: %+v", st)
	}
}

func TestSaveEnrollmentRejectsGarbage(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if err := s.SaveEnrollment(&protocol.EnrollResponse{CertificatePEM: "çöp"}, time.Now()); err == nil {
		t.Fatal("PEM olmayan sertifika reddedilmeli")
	}
}

func TestPinActionKey(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	if s.ActionKey() != nil {
		t.Fatal("başlangıçta anahtar olmamalı")
	}
	k1 := make([]byte, 32)
	k1[0] = 1
	k2 := make([]byte, 32)
	k2[0] = 2
	if err := s.PinActionKey(k1); err != nil {
		t.Fatal(err)
	}
	if err := s.PinActionKey(k1); err != nil {
		t.Errorf("aynı anahtar kabul edilmeli: %v", err)
	}
	if err := s.PinActionKey(k2); !errors.Is(err, ErrActionKeyMismatch) {
		t.Errorf("farklı anahtar reddedilmeli: %v", err)
	}
	if got := s.ActionKey(); got[0] != 1 {
		t.Error("sabitlenen anahtar değişmemeli")
	}
}

// selfSigned, anahtar için verilen süreyle kendinden imzalı sertifika üretir.
func selfSigned(t *testing.T, s Store, serial int64, from, to time.Time) []byte {
	t.Helper()
	key, err := s.LoadOrCreateKey()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "ajan-1"},
		NotBefore: from, NotAfter: to}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestSaveCertificate(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	now := time.Now()
	old := selfSigned(t, s, 1, now.Add(-time.Hour), now.Add(time.Hour))
	if err := s.SaveEnrollment(&protocol.EnrollResponse{AgentID: "ajan-1", Status: "active",
		CertificatePEM: string(old), CACertificatePEM: string(old)}, now); err != nil {
		t.Fatal(err)
	}

	// Başka bir anahtarın sertifikası kaydedilmez; eski sertifika yerinde kalır.
	other := selfSigned(t, Store{Dir: t.TempDir()}, 2, now, now.Add(time.Hour))
	if _, err := s.SaveCertificate(other); err == nil {
		t.Fatal("anahtarla eşleşmeyen sertifika reddedilmeli")
	}
	if b, _ := os.ReadFile(filepath.Join(s.Dir, certFile)); string(b) != string(old) {
		t.Fatal("reddedilen sertifika eskisinin yerine yazılmamalı")
	}

	renewed := selfSigned(t, s, 3, now, now.Add(48*time.Hour))
	cert, err := s.SaveCertificate(renewed)
	if err != nil {
		t.Fatal(err)
	}
	if _, loaded, err := s.Load(); err != nil || string(loaded.Certificate[0]) != string(cert.Certificate[0]) {
		t.Fatalf("yenilenen sertifika yüklenmeli: %v", err)
	}
}

func TestRenewDue(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name     string
		from, to time.Time
		want     bool
	}{
		{"yeni", now.Add(-time.Hour), now.Add(99 * time.Hour), false},
		{"yarısı geçti", now.Add(-60 * time.Hour), now.Add(40 * time.Hour), true},
		{"süresi doldu", now.Add(-100 * time.Hour), now.Add(-time.Hour), true},
	}
	for _, c := range cases {
		s := Store{Dir: t.TempDir()}
		cert, err := tlsPair(s, selfSigned(t, s, 1, c.from, c.to))
		if err != nil {
			t.Fatal(err)
		}
		if got := RenewDue(cert, now); got != c.want {
			t.Errorf("%s: RenewDue = %v, beklenen %v", c.name, got, c.want)
		}
	}
}

func tlsPair(s Store, certPEM []byte) (*tls.Certificate, error) {
	key, err := os.ReadFile(filepath.Join(s.Dir, keyFile))
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(certPEM, key)
	return &c, err
}
