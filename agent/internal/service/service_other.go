//go:build !windows

package service

import "context"

// IsService, Windows dışındaki platformlarda her zaman false döner.
func IsService() bool { return false }

// Run, Windows dışında run fonksiyonunu doğrudan çalıştırır.
func Run(run func(ctx context.Context) error) error { return run(context.Background()) }
