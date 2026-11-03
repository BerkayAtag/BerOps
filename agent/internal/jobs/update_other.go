//go:build !windows && !darwin

package jobs

import "context"

// StartUpdate, desteklenmeyen platformlarda hata döner.
func StartUpdate(context.Context, UpdateSpec) (UpdateWait, error) { return nil, errUpdateUnsupported }

// FinishUpdate, desteklenmeyen platformlarda bir şey yapmaz.
func FinishUpdate(string) {}
