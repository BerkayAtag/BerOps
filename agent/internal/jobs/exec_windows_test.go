//go:build windows

package jobs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestExecuteWindowsShells(t *testing.T) {
	dir := t.TempDir()
	res := Execute(context.Background(), Spec{Shell: protocol.ShellPowerShell, WorkDir: dir, Timeout: time.Minute,
		Command: "Write-Output 'merhaba ğüşıöç'\nWrite-Error 'uyarı' 2>&1 | Out-Null\nexit 7"})
	if res.Err != nil || res.ExitCode != 7 || !strings.Contains(res.Stdout, "merhaba ğüşıöç") {
		t.Errorf("PowerShell = %+v", res)
	}
	res = Execute(context.Background(), Spec{Shell: protocol.ShellCmd, WorkDir: dir, Timeout: time.Minute,
		Command: "echo cmd \"tırnak\" & exit /b 3"})
	if res.Err != nil || res.ExitCode != 3 || !strings.Contains(res.Stdout, `cmd "tırnak"`) {
		t.Errorf("cmd = %+v", res)
	}
	start := time.Now()
	res = Execute(context.Background(), Spec{Shell: protocol.ShellPowerShell, WorkDir: dir, Timeout: 2 * time.Second,
		Command: "Start-Process -NoNewWindow ping -ArgumentList '-n','60','127.0.0.1'; Start-Sleep 60"})
	if res.Err == nil || !strings.Contains(res.Err.Error(), "zaman aşımı") || time.Since(start) > 30*time.Second {
		t.Errorf("zaman aşımı = %+v (%s)", res, time.Since(start))
	}
}
