//go:build !windows && !darwin

package sysres

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// LowerProcessPriority, desteklenmeyen platformlarda bir şey yapmaz.
func LowerProcessPriority() error { return nil }

// RunLowPriority, desteklenmeyen platformlarda komutu doğrudan çalıştırır.
func RunLowPriority(ctx context.Context, _ int, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, firstLine(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// OnBattery, desteklenmeyen platformlarda bilinmez.
func OnBattery() (bool, error) { return false, ErrUnsupported }

// UserActive, desteklenmeyen platformlarda bilinmez.
func UserActive(time.Duration) (bool, error) { return false, ErrUnsupported }
