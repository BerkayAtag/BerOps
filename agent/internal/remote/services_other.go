//go:build !windows && !darwin

package remote

import (
	"context"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// ListServices bu platformda desteklenmez.
func ListServices(context.Context) ([]protocol.ServiceInfo, error) { return nil, ErrUnsupported }

// ControlService bu platformda desteklenmez.
func ControlService(context.Context, string, string) error { return ErrUnsupported }
