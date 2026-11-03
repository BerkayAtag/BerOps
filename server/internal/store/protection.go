package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// AgentProtection, kaldırma korumasının kayıtlı durumudur.
type AgentProtection struct {
	protocol.UninstallProtection
	UpdatedAt *time.Time
}

// GetAgentProtection, kaldırma korumasını okur; kayıt yoksa koruma kapalıdır.
func (s *Store) GetAgentProtection(ctx context.Context) (AgentProtection, error) {
	var p AgentProtection
	var iter *int32
	err := s.pool.QueryRow(ctx, `SELECT enabled, salt, hash, iterations, updated_at FROM agent_protection WHERE id = 1`).
		Scan(&p.Enabled, &p.Salt, &p.Hash, &iter, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, nil
	}
	if iter != nil {
		p.Iterations = int(*iter)
	}
	return p, err
}

// SaveAgentProtection, kaldırma korumasını kaydeder. Koruma kapatılınca özet silinir.
func (s *Store) SaveAgentProtection(ctx context.Context, p protocol.UninstallProtection, userID string, at time.Time) error {
	if !p.Enabled {
		p = protocol.UninstallProtection{}
	}
	var iter any
	if p.Iterations > 0 {
		iter = p.Iterations
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agent_protection (id, enabled, salt, hash, iterations, updated_at, updated_by)
		VALUES (1, $1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET enabled = EXCLUDED.enabled, salt = EXCLUDED.salt, hash = EXCLUDED.hash,
			iterations = EXCLUDED.iterations, updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by`,
		p.Enabled, p.Salt, p.Hash, iter, at, nullableUUID(userID))
	return err
}
