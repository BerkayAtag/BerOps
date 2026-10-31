package store

import (
	"context"
	"time"
)

// Denetim kaydı aktör türleri ve sonuçları.
const (
	ActorUser   = "user"
	ActorAgent  = "agent"
	ActorSystem = "system"

	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultDenied  = "denied"
)

// AuditEntry, denetim kaydının bir satırıdır.
type AuditEntry struct {
	ID         int64          `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	ActorType  string         `json:"actor_type"`
	ActorID    string         `json:"actor_id"`
	ActorName  string         `json:"actor_name"`
	Action     string         `json:"action"`
	TargetType string         `json:"target_type"`
	TargetID   string         `json:"target_id"`
	Params     map[string]any `json:"params"`
	Result     string         `json:"result"`
	Detail     string         `json:"detail"`
	SourceIP   string         `json:"source_ip"`
}

// AppendAudit, denetim kaydına satır ekler. Tablo trigger'larla güncelleme ve silmeye kapalıdır.
func (s *Store) AppendAudit(ctx context.Context, e AuditEntry) error {
	if e.Params == nil {
		e.Params = map[string]any{}
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now()
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_log (occurred_at, actor_type, actor_id, actor_name, action, target_type, target_id,
			params, result, detail, source_ip)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		e.OccurredAt, e.ActorType, e.ActorID, e.ActorName, e.Action, e.TargetType, e.TargetID,
		e.Params, e.Result, e.Detail, e.SourceIP)
	return err
}

// ListAudit, en yeni denetim kayıtlarını döner. Filtreleme ve dışa aktarma Aşama 5'te eklenir.
func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, actor_type, actor_id, actor_name, action, target_type, target_id,
		       params, result, detail, source_ip
		FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorType, &e.ActorID, &e.ActorName, &e.Action,
			&e.TargetType, &e.TargetID, &e.Params, &e.Result, &e.Detail, &e.SourceIP); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
