//go:build windows

package remote

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

var stateNames = map[svc.State]string{
	svc.Stopped: "stopped", svc.StartPending: "starting", svc.StopPending: "stopping", svc.Running: "running",
	svc.ContinuePending: "starting", svc.PausePending: "stopping", svc.Paused: "paused",
}

var startNames = map[uint32]string{
	mgr.StartAutomatic: "automatic", mgr.StartManual: "manual", mgr.StartDisabled: "disabled",
	windows.SERVICE_BOOT_START: "boot", windows.SERVICE_SYSTEM_START: "system",
}

// ListServices, Windows servislerini listeler.
func ListServices(context.Context) ([]protocol.ServiceInfo, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()
	names, err := m.ListServices()
	if err != nil {
		return nil, err
	}
	out := make([]protocol.ServiceInfo, 0, len(names))
	for _, n := range names {
		s, err := m.OpenService(n)
		if err != nil {
			continue
		}
		info := protocol.ServiceInfo{Name: n, State: "unknown"}
		if st, err := s.Query(); err == nil {
			info.State = stateNames[st.State]
			info.PID = int(st.ProcessId)
		}
		if c, err := s.Config(); err == nil {
			info.DisplayName = c.DisplayName
			info.StartType = startNames[c.StartType]
			if c.DelayedAutoStart && c.StartType == mgr.StartAutomatic {
				info.StartType = "automatic_delayed"
			}
		}
		s.Close()
		out = append(out, info)
	}
	slices.SortFunc(out, func(a, b protocol.ServiceInfo) int {
		return strings.Compare(strings.ToLower(a.DisplayName), strings.ToLower(b.DisplayName))
	})
	return out, nil
}

// ControlService, servisi başlatır, durdurur veya yeniden başlatır ve hedef duruma ulaşmasını bekler.
func ControlService(ctx context.Context, name, action string) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("servis açılamadı: %w", err)
	}
	defer s.Close()
	stop := func() error {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Stopped {
			return nil
		}
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("servis durdurulamadı: %w", err)
		}
		return wait(ctx, s, svc.Stopped)
	}
	start := func() error {
		if err := s.Start(); err != nil {
			return fmt.Errorf("servis başlatılamadı: %w", err)
		}
		return wait(ctx, s, svc.Running)
	}
	switch action {
	case "start":
		return start()
	case "stop":
		return stop()
	case "restart":
		if err := stop(); err != nil {
			return err
		}
		return start()
	}
	return fmt.Errorf("geçersiz işlem: %s", action)
}

func wait(ctx context.Context, s *mgr.Service, want svc.State) error {
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("servis beklenen duruma geçmedi (%s)", stateNames[st.State])
		case <-time.After(300 * time.Millisecond):
		}
	}
}
