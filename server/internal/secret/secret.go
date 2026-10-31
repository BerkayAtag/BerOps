// Package secret, veritabanında saklanan gizli değerleri (AD hizmet hesabı parolası gibi)
// sunucunun veri dizinindeki anahtarla AES-256-GCM kullanarak şifreler.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keyFile = "secret.key"

// Box, şifreleme anahtarıdır.
type Box struct {
	aead cipher.AEAD
}

// LoadOrCreate, anahtarı dizinden yükler; yoksa üretir (0600). Anahtar kaybolursa şifreli
// değerler (ör. AD parolası) yeniden girilmelidir.
func LoadOrCreate(dir string) (*Box, error) {
	path := filepath.Join(dir, keyFile)
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return New(key)
}

// New, 32 baytlık anahtarla kutu oluşturur.
func New(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("gizli anahtar 32 bayt olmalı, %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// NewRandom, testler için rastgele anahtarlı kutu üretir.
func NewRandom() *Box {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	b, _ := New(key)
	return b
}

// Seal, değeri şifreler; sonuç nonce + şifreli metindir. label, şifreli değerin başka bir
// alana taşınmasını önlemek için ek doğrulanmış veri olarak kullanılır.
func (b *Box) Seal(plain []byte, label string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, plain, []byte(label)), nil
}

// ErrDecrypt, şifre çözülemediğinde döner (anahtar değişmiş veya veri bozulmuş).
var ErrDecrypt = errors.New("gizli değer çözülemedi")

// Open, Seal ile şifrelenmiş değeri çözer.
func (b *Box) Open(sealed []byte, label string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, ErrDecrypt
	}
	out, err := b.aead.Open(nil, sealed[:n], sealed[n:], []byte(label))
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}
