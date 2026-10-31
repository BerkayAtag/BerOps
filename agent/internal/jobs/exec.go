package jobs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// Execute, komutu platformun kabuğunda çalıştırır. Komut önce iş dizinine betik dosyası olarak
// yazılır; böylece tırnak ve satır sonu kaçışlama sorunları oluşmaz. Zaman aşımında komutun
// başlattığı tüm alt süreçler de sonlandırılır.
func Execute(ctx context.Context, s Spec) Result {
	if s.Installer == protocol.InstallerDMG && s.Command == "" {
		return installDMG(ctx, s)
	}
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	cmd, err := scriptCommand(ctx, s)
	if err != nil {
		return Result{ExitCode: -1, Err: err}
	}
	return runCmd(ctx, cmd, s.Timeout)
}

// runCmd, hazırlanan komutu çalıştırıp sonucu toplar.
func runCmd(ctx context.Context, cmd *exec.Cmd, timeout time.Duration) Result {
	stdout := &limitedBuffer{limit: protocol.MaxOutputBytes}
	stderr := &limitedBuffer{limit: protocol.MaxOutputBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 10 * time.Second
	err := startAndWait(cmd)
	res := Result{Stdout: stdout.String(), Stderr: stderr.String()}
	var exitErr *exec.ExitError
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		res.ExitCode, res.Err = -1, fmt.Errorf("zaman aşımı (%s); komut ve alt süreçleri sonlandırıldı", timeout)
	case errors.As(err, &exitErr):
		res.ExitCode = exitErr.ExitCode()
	case err != nil:
		res.ExitCode, res.Err = -1, err
	}
	return res
}

func writeScript(dir, name string, body []byte) (string, error) {
	p := filepath.Join(dir, name)
	return p, os.WriteFile(p, body, 0o700)
}

var errUnsupportedInstaller = errors.New("bu yükleyici türü bu platformda desteklenmiyor")
