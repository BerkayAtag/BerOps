package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func mustCert(t *testing.T, tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c, key
}

func newCA(t *testing.T, serial int64) (*x509.Certificate, *ecdsa.PrivateKey) {
	return mustCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: "CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, nil)
}

func newLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, host string) *x509.Certificate {
	c, _ := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, caKey)
	return c
}

func TestVerifyChain(t *testing.T) {
	ca, caKey := newCA(t, 1)
	other, otherKey := newCA(t, 2)
	leaf := newLeaf(t, ca, caKey, "ber.example.test")
	pin := Fingerprint(ca)

	if err := VerifyChain([]*x509.Certificate{leaf, ca}, pin, "ber.example.test"); err != nil {
		t.Fatalf("geçerli zincir reddedildi: %v", err)
	}
	if err := VerifyChain([]*x509.Certificate{leaf, ca}, Fingerprint(other), "ber.example.test"); err == nil {
		t.Error("farklı CA pin'i reddedilmeliydi")
	}
	if err := VerifyChain([]*x509.Certificate{leaf, ca}, pin, "baska.example.test"); err == nil {
		t.Error("yanlış ana makine adı reddedilmeliydi")
	}
	// Saldırgan pin'lenmiş CA'yı zincire ekleyip kendi CA'sıyla imzalanmış sertifika sunarsa:
	forged := newLeaf(t, other, otherKey, "ber.example.test")
	if err := VerifyChain([]*x509.Certificate{forged, ca}, pin, "ber.example.test"); err == nil {
		t.Error("pin'lenmiş CA tarafından imzalanmamış sertifika reddedilmeliydi")
	}
	if err := VerifyChain(nil, pin, "ber.example.test"); err == nil {
		t.Error("boş zincir reddedilmeliydi")
	}
}

func TestNormalize(t *testing.T) {
	want := "sha256:abcdef01"
	for _, in := range []string{"sha256:abcdef01", "ABCDEF01", " sha256:AB:CD:EF:01 "} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestConfigRequiresPin(t *testing.T) {
	if _, err := Config("  ", "host"); err == nil {
		t.Fatal("boş pin reddedilmeliydi")
	}
}
