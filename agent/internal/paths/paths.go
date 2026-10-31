// Package paths, ajanın platforma göre varsayılan veri dizinini belirler.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDataDir, ajan yapılandırması, kimliği ve loglarının bulunduğu dizindir.
func DefaultDataDir() string {
	switch runtime.GOOS {
	case "windows":
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "BER", "Agent")
	case "darwin":
		return "/Library/Application Support/BER/Agent"
	default:
		return "/var/lib/ber-agent"
	}
}
