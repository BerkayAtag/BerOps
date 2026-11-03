package protocol

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
)

// UninstallCodeIterations, kaldırma kodu özetinin PBKDF2-SHA256 tur sayısıdır.
const UninstallCodeIterations = 200_000

// UninstallProtection, ajanın kaldırılmasını bir koda bağlar. Kodun kendisi ajana gönderilmez;
// yalnızca tuzlu PBKDF2-SHA256 özeti gönderilir.
type UninstallProtection struct {
	Enabled    bool   `json:"enabled"`
	Salt       []byte `json:"salt,omitempty"`
	Hash       []byte `json:"hash,omitempty"`
	Iterations int    `json:"iterations,omitempty"`
}

// HashUninstallCode, kodun özetini üretir.
func HashUninstallCode(code string, salt []byte, iterations int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, code, salt, iterations, 32)
}

// Allows, kodun kaldırmaya izin verip vermediğini döner. Koruma kapalıysa her kod kabul edilir.
func (p *UninstallProtection) Allows(code string) bool {
	if p == nil || !p.Enabled {
		return true
	}
	if len(p.Salt) < 16 || len(p.Hash) != 32 || p.Iterations < 10_000 || code == "" {
		return false
	}
	h, err := HashUninstallCode(code, p.Salt, p.Iterations)
	return err == nil && subtle.ConstantTimeCompare(h, p.Hash) == 1
}
