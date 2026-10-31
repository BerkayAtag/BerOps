//go:build windows

package service

import (
	"context"

	"golang.org/x/sys/windows/svc"
)

// IsService, sürecin Windows servisi olarak başlatılıp başlatılmadığını döner.
func IsService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// Run, run fonksiyonunu name adlı servis olarak çalıştırır; SCM durdurma isteği bağlamı
// iptal eder.
func Run(name string, run func(ctx context.Context) error) error {
	return svc.Run(name, &handler{run: run})
}

type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			if err != nil {
				return true, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			}
		}
	}
}
