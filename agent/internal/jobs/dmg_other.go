//go:build !darwin && !windows

package jobs

import "context"

func installDMG(context.Context, Spec) Result {
	return Result{ExitCode: -1, Err: errUnsupportedInstaller}
}
