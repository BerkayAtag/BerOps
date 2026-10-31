//go:build windows

package sysres

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LowerProcessPriority, ajan sürecini BELOW_NORMAL önceliğe alır.
func LowerProcessPriority() error {
	return windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
}

const (
	jobObjectCPURateControlInformation = 15
	cpuRateControlEnable               = 0x1
	cpuRateControlHardCap              = 0x4
)

// jobCPURateControl, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION yapısıdır (CpuRate birliği).
type jobCPURateControl struct {
	ControlFlags uint32
	CPURate      uint32 // yüzde × 100 (ör. %10 = 1000)
}

// newLimitedJob, kapatıldığında içindeki süreçleri sonlandıran ve toplam CPU kullanımını
// sert biçimde sınırlayan bir Job Object üretir.
func newLimitedJob(cpuLimitPercent int) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	ext := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	ext.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&ext)), uint32(unsafe.Sizeof(ext))); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	if cpuLimitPercent > 0 && cpuLimitPercent < 100 {
		rc := jobCPURateControl{ControlFlags: cpuRateControlEnable | cpuRateControlHardCap, CPURate: uint32(cpuLimitPercent * 100)}
		if _, err := windows.SetInformationJobObject(job, jobObjectCPURateControlInformation,
			uintptr(unsafe.Pointer(&rc)), uint32(unsafe.Sizeof(rc))); err != nil {
			windows.CloseHandle(job)
			return 0, fmt.Errorf("CPU sınırı uygulanamadı: %w", err)
		}
	}
	return job, nil
}

// RunLowPriority, komutu IDLE önceliğinde, penceresiz ve CPU sınırlı bir Job Object
// içinde çalıştırır; standart çıktıyı döner.
func RunLowPriority(ctx context.Context, cpuLimitPercent int, env []string, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.IDLE_PRIORITY_CLASS | windows.CREATE_NO_WINDOW,
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second

	job, jobErr := newLimitedJob(cpuLimitPercent)
	if err := cmd.Start(); err != nil {
		if jobErr == nil {
			windows.CloseHandle(job)
		}
		return nil, err
	}
	if jobErr == nil {
		defer windows.CloseHandle(job)
		if h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid)); err == nil {
			_ = windows.AssignProcessToJobObject(job, h)
			windows.CloseHandle(h)
		}
	}
	err := cmd.Wait()
	if err != nil {
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, firstLine(stderr.String()))
	}
	return stdout.Bytes(), nil
}

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

var procGetSystemPowerStatus = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemPowerStatus")

// OnBattery, makine pille çalışıyorsa true döner.
func OnBattery() (bool, error) {
	var st systemPowerStatus
	r, _, err := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&st)))
	if r == 0 {
		return false, err
	}
	const noBattery = 128
	return st.ACLineStatus == 0 && st.BatteryFlag&noBattery == 0, nil
}

// UserActive, Windows servisleri oturum 0'da çalıştığı için kullanıcı girdisini göremez.
// Bu kontrol Windows'ta desteklenmez (bkz. docs/varsayimlar.md).
func UserActive(time.Duration) (bool, error) {
	return false, ErrUnsupported
}
