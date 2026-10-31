//go:build !windows

package jobs

import (
	"context"
	"os/exec"
	"syscall"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func scriptCommand(ctx context.Context, s Spec) (*exec.Cmd, error) {
	shell := "/bin/sh"
	if s.Shell == protocol.ShellZsh {
		shell = "/bin/zsh"
	}
	path, err := writeScript(s.WorkDir, "komut.sh", []byte(s.Command+"\n"))
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, shell, path)
	cmd.Dir = s.WorkDir
	// Komut kendi süreç grubunda çalışır; zaman aşımında grubun tamamı sonlandırılır.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		pgid := cmd.Process.Pid
		err := syscall.Kill(-pgid, syscall.SIGKILL)
		// macOS'ta sinyal anında çatallanmakta olan bir süreç gruptan kaçabilir; kısa bir
		// süre sonra grup yeniden sonlandırılır.
		time.AfterFunc(200*time.Millisecond, func() { _ = syscall.Kill(-pgid, syscall.SIGKILL) })
		return err
	}
	return cmd, nil
}

func startAndWait(cmd *exec.Cmd) error { return cmd.Run() }
