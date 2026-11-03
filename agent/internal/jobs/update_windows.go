//go:build windows

package jobs

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// StartUpdate, msiexec'i ajandan bağımsız başlatır. Süreç, ajanın komutlar için kullandığı ve
// kapanınca içindekileri sonlandıran Job Object'e alınmaz; MSI ajan servisini durdurduğunda
// kurulum sürer.
func StartUpdate(_ context.Context, u UpdateSpec) (UpdateWait, error) {
	msiexec := filepath.Join(os.Getenv("SystemRoot"), "System32", "msiexec.exe")
	newCmd := func(flags uint32) *exec.Cmd {
		cmd := exec.Command(msiexec, "/i", u.File, "/qn", "/norestart", "/l*v", u.LogFile)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
		return cmd
	}
	base := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_NEW_PROCESS_GROUP)
	cmd := newCmd(base | windows.CREATE_BREAKAWAY_FROM_JOB)
	if err := cmd.Start(); err != nil {
		// Ajan, ayrılmaya izin vermeyen bir Job Object içindeyse bayraksız denenir.
		cmd = newCmd(base)
		if err := cmd.Start(); err != nil {
			return nil, err
		}
	}
	done := make(chan int, 1)
	go func() {
		_ = cmd.Wait()
		done <- cmd.ProcessState.ExitCode()
	}()
	return func(ctx context.Context) (int, error) {
		select {
		case <-ctx.Done():
			return -1, ctx.Err()
		case code := <-done:
			return code, nil
		}
	}, nil
}

// FinishUpdate, güncellemeden kalan geçici kaynakları temizler (Windows'ta gerek yok).
func FinishUpdate(string) {}
