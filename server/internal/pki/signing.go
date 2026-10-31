package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// signingKeyFile, aksiyon imza anahtarının PKI dizinindeki adıdır.
const signingKeyFile = "action-signing.key"

// LoadOrCreateSigningKey, ajanlara gönderilen işleri imzalayan Ed25519 anahtarını yükler;
// yoksa üretir. Anahtar yalnızca sunucuda durur; ajanlar açık anahtarı kayıt sırasında
// (veya ilk heartbeat'te) öğrenip sabitler. Veritabanına erişen bir saldırgan bu anahtar
// olmadan ajanlara çalıştırılabilir iş ekleyemez.
func LoadOrCreateSigningKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, signingKeyFile)
	b, err := os.ReadFile(path)
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("aksiyon imza anahtarı PEM biçiminde değil")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("aksiyon imza anahtarı okunamadı: %w", err)
		}
		key, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("aksiyon imza anahtarı Ed25519 değil")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// NewSigningKey, testler için bellekte imza anahtarı üretir.
func NewSigningKey() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return key
}
