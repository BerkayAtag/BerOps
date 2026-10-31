//go:build darwin

package remote

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

var labelRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)

// domain, launchd alanıdır: ajan root olarak çalışıyorsa sistem, değilse kullanıcı alanı.
func domain() string {
	if os.Geteuid() == 0 {
		return "system"
	}
	return "gui/" + strconv.Itoa(os.Getuid())
}

// ListServices, launchd işlerini "launchctl list" çıktısından okur.
func ListServices(ctx context.Context) ([]protocol.ServiceInfo, error) {
	out, err := exec.CommandContext(ctx, "/bin/launchctl", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("launchctl list: %w", err)
	}
	var list []protocol.ServiceInfo
	sc := bufio.NewScanner(bytes.NewReader(out))
	first := true
	for sc.Scan() {
		if first {
			first = false // başlık satırı: PID Status Label
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		info := protocol.ServiceInfo{Name: f[2], State: "stopped"}
		if pid, err := strconv.Atoi(f[0]); err == nil {
			info.PID, info.State = pid, "running"
		}
		list = append(list, info)
	}
	slices.SortFunc(list, func(a, b protocol.ServiceInfo) int { return strings.Compare(a.Name, b.Name) })
	return list, nil
}

// ControlService, launchd işini yeniden başlatır veya durdurur ("launchctl kickstart/kill").
// macOS'ta işin kalıcı olarak etkinleştirilmesi/devre dışı bırakılması desteklenmez.
func ControlService(ctx context.Context, name, action string) error {
	if !labelRe.MatchString(name) {
		return fmt.Errorf("geçersiz servis adı")
	}
	target := domain() + "/" + name
	var args []string
	switch action {
	case "start", "restart":
		args = []string{"kickstart", "-k", target}
		if action == "start" {
			args = []string{"kickstart", target}
		}
	case "stop":
		args = []string{"kill", "SIGTERM", target}
	default:
		return fmt.Errorf("geçersiz işlem: %s", action)
	}
	if out, err := exec.CommandContext(ctx, "/bin/launchctl", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl %s: %v: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return nil
}
