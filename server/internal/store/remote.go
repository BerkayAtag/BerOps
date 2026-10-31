package store

import (
	"context"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// RemoteSettings, uzaktan yönetimin genel ayarlarıdır.
type RemoteSettings struct {
	Enabled        bool `json:"enabled"`
	SessionMinutes int  `json:"session_minutes"`
}

// GetRemoteSettings, genel ayarları döner (kayıt yoksa kapalı).
func (s *Store) GetRemoteSettings(ctx context.Context) (RemoteSettings, error) {
	r := RemoteSettings{SessionMinutes: 10}
	err := s.pool.QueryRow(ctx, `SELECT enabled, session_minutes FROM remote_settings WHERE id = 1`).Scan(&r.Enabled, &r.SessionMinutes)
	if err := notFound(err); err != nil && err != ErrNotFound {
		return r, err
	}
	return r, nil
}

// SaveRemoteSettings, genel ayarları kaydeder.
func (s *Store) SaveRemoteSettings(ctx context.Context, r RemoteSettings, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO remote_settings (id, enabled, session_minutes, updated_by) VALUES (1, $1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, session_minutes = EXCLUDED.session_minutes,
			updated_at = now(), updated_by = EXCLUDED.updated_by`, r.Enabled, r.SessionMinutes, nullableUUID(userID))
	return err
}

// GetMachineRemote, makinenin uzaktan yönetim bayraklarını döner (kayıt yoksa hepsi kapalı).
func (s *Store) GetMachineRemote(ctx context.Context, machineID string) (protocol.RemoteFlags, error) {
	var f protocol.RemoteFlags
	err := s.pool.QueryRow(ctx, `SELECT performance, services, registry_read, registry_write FROM machine_remote
		WHERE machine_id = $1`, machineID).Scan(&f.Performance, &f.Services, &f.RegistryRead, &f.RegistryWrite)
	if err := notFound(err); err != nil && err != ErrNotFound {
		return f, err
	}
	return f, nil
}

// SaveMachineRemote, makinenin bayraklarını kaydeder.
func (s *Store) SaveMachineRemote(ctx context.Context, machineID string, f protocol.RemoteFlags, userID string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO machine_remote (machine_id, performance, services, registry_read, registry_write, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (machine_id) DO UPDATE SET performance = EXCLUDED.performance, services = EXCLUDED.services,
			registry_read = EXCLUDED.registry_read, registry_write = EXCLUDED.registry_write,
			updated_at = now(), updated_by = EXCLUDED.updated_by`,
		machineID, f.Performance, f.Services, f.RegistryRead, f.RegistryWrite, nullableUUID(userID))
	return err
}
