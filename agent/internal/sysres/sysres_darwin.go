//go:build darwin

package sysres

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// LowerProcessPriority, ajan sürecinin nice değerini 10 yapar.
func LowerProcessPriority() error {
	return unix.Setpriority(unix.PRIO_PROCESS, 0, 10)
}

// RunLowPriority, komutu `taskpolicy -b` ile arka plan (en düşük CPU ve disk önceliği)
// sınıfında çalıştırır. macOS'ta süreç başına sert CPU sınırı bulunmadığından sınır
// arka plan QoS sınıfıyla sağlanır (bkz. docs/varsayimlar.md).
func RunLowPriority(ctx context.Context, _ int, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "/usr/sbin/taskpolicy", append([]string{"-b", name}, args...)...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return append(stdout.Bytes(), stderr.Bytes()...), fmt.Errorf("%w: %s", err, firstLine(stderr.String()))
	}
	// softwareupdate gibi araçlar bilgi mesajlarını stderr'e yazar; ikisi birlikte döner.
	return append(stdout.Bytes(), stderr.Bytes()...), nil
}

// OnBattery, `pmset -g batt` çıktısına göre pil gücüyle çalışılıp çalışılmadığını döner.
func OnBattery() (bool, error) {
	out, err := exec.Command("/usr/bin/pmset", "-g", "batt").Output()
	if err != nil {
		return false, err
	}
	return strings.Contains(string(out), "'Battery Power'"), nil
}

var hidIdleRe = regexp.MustCompile(`"HIDIdleTime"\s*=\s*(\d+)`)

// UserActive, son kullanıcı girdisinden bu yana geçen süre threshold'dan kısaysa true döner.
func UserActive(threshold time.Duration) (bool, error) {
	out, err := exec.Command("/usr/sbin/ioreg", "-c", "IOHIDSystem", "-d", "4").Output()
	if err != nil {
		return false, err
	}
	m := hidIdleRe.FindSubmatch(out)
	if m == nil {
		return false, ErrUnsupported
	}
	ns, err := strconv.ParseInt(string(m[1]), 10, 64)
	if err != nil {
		return false, err
	}
	return time.Duration(ns) < threshold, nil
}
