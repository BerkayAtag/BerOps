// Package auth; parola özetleme, oturum token'ları, giriş deneme sınırlaması ve
// rol/izin (RBAC) tanımlarını içerir.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parametreleri (OWASP önerisi: m=64 MiB, t=3, p=2 ile güvenli tarafta).
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16

	// MinPasswordLength, yerel hesaplar için en kısa parola uzunluğudur.
	MinPasswordLength = 12
)

// ErrPasswordMismatch, parola özetle eşleşmediğinde döner.
var ErrPasswordMismatch = errors.New("parola eşleşmiyor")

// HashPassword, parolayı PHC biçiminde Argon2id özetine dönüştürür:
// $argon2id$v=19$m=65536,t=3,p=2$<tuz>$<özet>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	sum := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(sum)), nil
}

// VerifyPassword, parolayı özetle sabit zamanda karşılaştırır. Özetteki parametreler
// kullanılır; böylece parametreler ileride artırılsa da eski özetler doğrulanabilir.
func VerifyPassword(encoded, password string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("desteklenmeyen parola özeti biçimi")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return errors.New("desteklenmeyen argon2 sürümü")
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return errors.New("parola özeti parametreleri okunamadı")
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return errors.New("parola özeti tuzu okunamadı")
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return errors.New("parola özeti okunamadı")
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// ValidatePasswordPolicy, yerel hesap parolasının asgari kurallara uymasını denetler.
func ValidatePasswordPolicy(password string) error {
	if len([]rune(password)) < MinPasswordLength {
		return fmt.Errorf("parola en az %d karakter olmalı", MinPasswordLength)
	}
	return nil
}
