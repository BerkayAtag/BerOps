//go:build windows

package jobs

import (
	"context"
	"os/exec"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// utf8BOM, Windows PowerShell 5.1'in betiği UTF-8 olarak okuması için gereklidir.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func scriptCommand(ctx context.Context, s Spec) (*exec.Cmd, error) {
	var cmd *exec.Cmd
	switch s.Shell {
	case protocol.ShellPowerShell:
		body := append(append([]byte{}, utf8BOM...),
			[]byte("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n$ProgressPreference = 'SilentlyContinue'\r\n"+
				s.Command+"\r\nexit $LASTEXITCODE\r\n")...)
		path, err := writeScript(s.WorkDir, "komut.ps1", body)
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	default:
		path, err := writeScript(s.WorkDir, "komut.cmd", []byte("@echo off\r\nchcp 65001 >nul\r\n"+s.Command+"\r\nexit /b %ERRORLEVEL%\r\n"))
		if err != nil {
			return nil, err
		}
		cmd = exec.CommandContext(ctx, "cmd.exe", "/d", "/c", path)
	}
	cmd.Dir = s.WorkDir
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	return cmd, nil
}

// startAndWait, süreci kapatıldığında içindekileri sonlandıran bir Job Object'e alır;
// zaman aşımında yükleyicinin başlattığı alt süreçler de (msiexec, setup.exe) sonlandırılır.
func startAndWait(cmd *exec.Cmd) error {
	job, err := windows.CreateJobObject(nil, nil)
	if err == nil {
		ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		_, _ = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext)))
		defer windows.CloseHandle(job)
		cmd.Cancel = func() error {
			_ = windows.TerminateJobObject(job, 1)
			return cmd.Process.Kill()
		}
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if job != 0 {
		if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
			_ = windows.AssignProcessToJobObject(job, h)
			windows.CloseHandle(h)
		}
	}
	return cmd.Wait()
}

func installDMG(_ context.Context, _ Spec) Result {
	return Result{ExitCode: -1, Err: errUnsupportedInstaller}
}
