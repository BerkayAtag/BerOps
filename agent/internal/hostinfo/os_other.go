//go:build !windows && !darwin

package hostinfo

import (
	"bufio"
	"os"
	"strings"
)

// readOSInfo, desteklenmeyen platformlarda (geliştirme amaçlı Linux) /etc/os-release'i okur.
// Sunucu yalnızca Windows ve macOS ajanlarını kabul eder.
func readOSInfo() OSInfo {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return OSInfo{Name: "unknown"}
	}
	defer f.Close()
	var info OSInfo
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"`)
		switch k {
		case "PRETTY_NAME":
			info.Name = v
		case "VERSION_ID":
			info.Version = v
		}
	}
	return info
}
