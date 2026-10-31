//go:build darwin

package hostinfo

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// readOSInfo, sürüm bilgisini sw_vers ile okur.
func readOSInfo() OSInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	get := func(flag string) string {
		out, err := exec.CommandContext(ctx, "/usr/bin/sw_vers", flag).Output()
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(out))
	}
	name := get("-productName")
	if name == "" {
		name = "macOS"
	}
	return OSInfo{Name: name, Version: get("-productVersion"), Build: get("-buildVersion")}
}
