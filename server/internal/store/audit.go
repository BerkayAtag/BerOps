package store

import (
	"context"
	"strconv"
	"strings"
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

// AuditFilter, denetim kaydı arama parametreleridir.
type AuditFilter struct {
	Search string // aktör, eylem, hedef veya ayrıntı içinde
	Action string // önek (ör. "action." veya "auth.login")
	Result string
	Actor  string
	From   *time.Time
	To     *time.Time
	Limit  int
	Offset int
}

// ListAudit, filtreye uyan kayıtları yeniden eskiye ve toplam sayıyı döner.
func (s *Store) ListAudit(ctx context.Context, f AuditFilter) ([]AuditEntry, int, error) {
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		p := arg("%" + escapeLike(q) + "%")
		where = append(where, "(actor_name ILIKE "+p+" OR action ILIKE "+p+" OR target_id ILIKE "+p+
			" OR detail ILIKE "+p+" OR source_ip ILIKE "+p+" OR params::text ILIKE "+p+")")
	}
	if f.Action != "" {
		where = append(where, "action LIKE "+arg(escapeLike(f.Action)+"%"))
	}
	if f.Result != "" {
		where = append(where, "result = "+arg(f.Result))
	}
	if f.Actor != "" {
		where = append(where, "lower(actor_name) = lower("+arg(f.Actor)+")")
	}
	if f.From != nil {
		where = append(where, "occurred_at >= "+arg(*f.From))
	}
	if f.To != nil {
		where = append(where, "occurred_at < "+arg(*f.To))
	}
	cond := ""
	if len(where) > 0 {
		cond = "WHERE " + strings.Join(where, " AND ")
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, occurred_at, actor_type, actor_id, actor_name, action, target_type, target_id,
		       params, result, detail, source_ip
		FROM audit_log `+cond+` ORDER BY id DESC LIMIT `+arg(limit)+` OFFSET `+arg(max(f.Offset, 0)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []AuditEntry{}
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.ActorType, &e.ActorID, &e.ActorName, &e.Action,
			&e.TargetType, &e.TargetID, &e.Params, &e.Result, &e.Detail, &e.SourceIP); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}
