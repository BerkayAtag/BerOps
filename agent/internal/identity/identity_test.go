package identity

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
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
