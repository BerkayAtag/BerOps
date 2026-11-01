package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// NewToken, URL güvenli 256 bit rastgele token üretir.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken, token'ın veritabanında saklanacak SHA-256 özetidir. Token'lar yüksek
// entropili olduğu için yavaş bir özet fonksiyonuna gerek yoktur.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// RegistrationKeyPrefix, kayıt anahtarlarının başına eklenen ve sızıntı taramalarında
// tanınmalarını sağlayan önektir.
const RegistrationKeyPrefix = "berreg_"

// NewRegistrationKey, yeni bir ajan kayıt anahtarı ve konsolda gösterilecek kısa önekini üretir.
func NewRegistrationKey() (key, displayPrefix string, err error) {
	t, err := NewToken()
	if err != nil {
		return "", "", err
	}
	key = RegistrationKeyPrefix + t
	return key, key[:len(RegistrationKeyPrefix)+6], nil
}

// APIKeyPrefix, dış sistemler için API anahtarlarının önekidir.
const APIKeyPrefix = "berops_"

// NewAPIKey, yeni bir API anahtarı ve konsolda gösterilecek kısa önekini üretir.
func NewAPIKey() (key, displayPrefix string, err error) {
	t, err := NewToken()
	if err != nil {
		return "", "", err
	}
	key = APIKeyPrefix + t
	return key, key[:len(APIKeyPrefix)+6], nil
}
