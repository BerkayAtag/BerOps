// Package protection, kaldırma korumasının ajandaki kopyasını (protection.json) yönetir.
// Sunucu kodun yalnızca tuzlu özetini gönderir; MSI ve macOS kaldırma betiği kaldırmadan
// önce "berops-agent uninstall-check" ile kodu doğrular.
package protection

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// FileName, veri dizinindeki koruma dosyasının adıdır.
const FileName = "protection.json"

// Load, koruma ayarını okur. Dosya yoksa koruma kapalıdır (nil).
func Load(dir string) (*protocol.UninstallProtection, error) {
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p protocol.UninstallProtection
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Apply, sunucudan gelen ayarı dosyaya yansıtır: koruma kapalıysa dosya silinir. Değişiklik
// yoksa dosyaya yazılmaz. Dosyanın değişip değişmediğini döner.
func Apply(dir string, p *protocol.UninstallProtection) (bool, error) {
	path := filepath.Join(dir, FileName)
	if p == nil || !p.Enabled {
		err := os.Remove(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return err == nil, err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return false, err
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, b) {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return false, err
	}
	return true, os.Rename(tmp, path)
}

// ErrWrongCode, kaldırma kodunun hatalı veya eksik olduğunu bildirir.
var ErrWrongCode = errors.New("kaldırma kodu hatalı veya verilmedi; kodu BerOps konsolundaki yöneticiden isteyin")

// Check, kaldırmaya izin verilip verilmediğini denetler. Koruma dosyası okunamıyorsa kaldırma
// reddedilir (kapalı hata).
func Check(dir, code string) error {
	p, err := Load(dir)
	if err != nil {
		return err
	}
	if !p.Allows(code) {
		return ErrWrongCode
	}
	return nil
}
