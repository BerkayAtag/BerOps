//go:build !windows && !darwin

package inventory

import (
	"context"
	"errors"

	"github.com/BerkayAtag/automation-ber/agent/internal/sysres"
)

// collectPlatform, desteklenmeyen platformlarda (geliştirme amaçlı Linux) envanter toplamaz.
func collectPlatform(_ context.Context, _ Options, _ *sysres.Throttle, s *Snapshot) {
	s.Errors = append(s.Errors, errors.New("envanter bu platformda desteklenmiyor").Error())
}
