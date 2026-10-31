//go:build darwin

package jobs

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// applicationsDir, .app paketlerinin kopyalandığı dizindir (testlerde değiştirilir).
var applicationsDir = "/Applications"

// installDMG, disk imajını salt okunur bağlar; içinde .pkg varsa installer ile kurar, yoksa
// ilk .app paketini Applications dizinine kopyalar (varsa eski sürümün yerine).
func installDMG(ctx context.Context, s Spec) Result {
	ctx, cancel := context.WithTimeout(ctx, s.Timeout)
	defer cancel()
	mnt, err := os.MkdirTemp(s.WorkDir, "dmg-")
	if err != nil {
		return Result{ExitCode: -1, Err: err}
	}
	var log strings.Builder
	run := func(name string, args ...string) error {
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		fmt.Fprintf(&log, "$ %s %s\n%s", name, strings.Join(args, " "), out)
		return err
	}
	if err := run("/usr/bin/hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-noverify", "-mountpoint", mnt, s.File); err != nil {
		return Result{ExitCode: -1, Stdout: log.String(), Err: fmt.Errorf("imaj bağlanamadı: %w", err)}
	}
	defer func() {
		_ = exec.Command("/usr/bin/hdiutil", "detach", mnt, "-force").Run()
	}()
	entries, err := os.ReadDir(mnt)
	if err != nil {
		return Result{ExitCode: -1, Stdout: log.String(), Err: err}
	}
	for _, e := range entries {
		if ext := strings.ToLower(filepath.Ext(e.Name())); ext == ".pkg" || ext == ".mpkg" {
			err := run("/usr/sbin/installer", "-pkg", filepath.Join(mnt, e.Name()), "-target", "/")
			return dmgResult(log.String(), err)
		}
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".app") && e.IsDir() {
			dst := filepath.Join(applicationsDir, e.Name())
			if err := os.RemoveAll(dst); err != nil {
				return Result{ExitCode: -1, Stdout: log.String(), Err: err}
			}
			err := run("/usr/bin/ditto", filepath.Join(mnt, e.Name()), dst)
			return dmgResult(log.String(), err)
		}
	}
	return Result{ExitCode: -1, Stdout: log.String(), Err: fmt.Errorf("imajda .pkg veya .app bulunamadı")}
}

func dmgResult(out string, err error) Result {
	if err != nil {
		code := -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return Result{ExitCode: code, Stdout: out, Err: err}
	}
	return Result{Stdout: out}
}
