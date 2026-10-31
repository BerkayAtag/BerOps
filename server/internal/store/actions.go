package store

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

// Aksiyon durumları.
const (
	ActionPendingApproval = "pending_approval"
	ActionActive          = "active"
	ActionCompleted       = "completed"
	ActionCancelled       = "cancelled"
	ActionRejected        = "rejected"
)

// NewTarget, aksiyonun imzalı hedefidir.
type NewTarget struct {
	MachineID string
	Payload   []byte
	Signature []byte
	Stage     int
}

// NewAction, oluşturulacak aksiyondur. ID, imzalı iş tanımında yer aldığı için önceden üretilir.
type NewAction struct {
	ID             string
	Name           string
	Kind           string
	PackageID      string
	Shell          string
	Command        string
	TimeoutSeconds int
	BandwidthKbps  int
	Status         string
	CreatedBy      string
	CreatedByName  string
	CreatedAt      time.Time
	ExpiresAt      time.Time
	Targets        []NewTarget
	RespectWindows bool
	Rollout        *Rollout
}

// Rollout, kademeli dağıtım planıdır.
type Rollout struct {
	Stages            []RolloutStage `json:"stages"`
	MinSuccessPercent int            `json:"min_success_percent"`
}

// RolloutStage, bir aşamadır: hedeflerin yüzdesi ve aksiyon oluşturulduktan sonra en erken
// kaç saat sonra açılacağı.
type RolloutStage struct {
	Percent    int `json:"percent"`
	DelayHours int `json:"delay_hours"`
}

// Action, aksiyon kaydı ve hedef durum sayaçlarıdır.
type Action struct {
	ID             string         `json:"id"`
	Name           string         `json:"name"`
	Kind           string         `json:"kind"`
	PackageID      *string        `json:"package_id"`
	PackageName    string         `json:"package_name"`
	PackageVersion string         `json:"package_version"`
	Shell          string         `json:"shell"`
	Command        string         `json:"command"`
	TimeoutSeconds int            `json:"timeout_seconds"`
	BandwidthKbps  int            `json:"bandwidth_kbps"`
	Status         string         `json:"status"`
	TargetCount    int            `json:"target_count"`
	CreatedBy      *string        `json:"created_by"`
	CreatedByName  string         `json:"created_by_name"`
	CreatedAt      time.Time      `json:"created_at"`
	ExpiresAt      time.Time      `json:"expires_at"`
	ApprovedAt     *time.Time     `json:"approved_at"`
	CompletedAt    *time.Time     `json:"completed_at"`
	Counts         map[string]int `json:"counts"`
	RespectWindows bool           `json:"respect_windows"`
	Rollout        *Rollout       `json:"rollout"`
	PausedReason   string         `json:"paused_reason"`
	// ReleasedStages, açılmış aşama sayısıdır (kademeli dağıtımda).
	ReleasedStages int `json:"released_stages"`
}

// CreateAction, aksiyonu ve imzalı hedeflerini tek transaction içinde yazar.
func (s *Store) CreateAction(ctx context.Context, a NewAction) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO actions (id, name, kind, package_id, shell, command, timeout_seconds, bandwidth_kbps, status,
				target_count, created_by, created_by_name, created_at, expires_at, respect_windows, rollout)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
			a.ID, a.Name, a.Kind, nullableUUID(a.PackageID), a.Shell, a.Command, a.TimeoutSeconds, a.BandwidthKbps,
			a.Status, len(a.Targets), nullableUUID(a.CreatedBy), a.CreatedByName, a.CreatedAt, a.ExpiresAt,
			a.RespectWindows, a.Rollout); err != nil {
			return err
		}
		rows := make([][]any, len(a.Targets))
		for i, t := range a.Targets {
			rows[i] = []any{a.ID, t.MachineID, protocol.TargetPending, t.Payload, t.Signature, a.CreatedAt, int16(t.Stage), t.Stage == 0}
		}
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"action_targets"},
			[]string{"action_id", "machine_id", "status", "payload", "signature", "updated_at", "stage", "released"}, pgx.CopyFromRows(rows))
		return err
	})
}

const actionSelect = `
	SELECT a.id, a.name, a.kind, a.package_id, coalesce(p.name, ''), coalesce(p.version, ''), a.shell, a.command,
	       a.timeout_seconds, a.bandwidth_kbps, a.status, a.target_count, a.created_by, a.created_by_name, a.created_at,
	       a.expires_at, a.approved_at, a.completed_at,
	       coalesce((SELECT jsonb_object_agg(status, n) FROM (SELECT status, count(*) n FROM action_targets t
	                 WHERE t.action_id = a.id GROUP BY status) c), '{}'),
	       a.respect_windows, a.rollout, a.paused_reason,
	       (SELECT count(DISTINCT stage) FROM action_targets t WHERE t.action_id = a.id AND t.released)
	FROM actions a LEFT JOIN packages p ON p.id = a.package_id`

func scanAction(row interface{ Scan(...any) error }) (*Action, error) {
	var a Action
	if err := row.Scan(&a.ID, &a.Name, &a.Kind, &a.PackageID, &a.PackageName, &a.PackageVersion, &a.Shell, &a.Command,
		&a.TimeoutSeconds, &a.BandwidthKbps, &a.Status, &a.TargetCount, &a.CreatedBy, &a.CreatedByName, &a.CreatedAt,
		&a.ExpiresAt, &a.ApprovedAt, &a.CompletedAt, &a.Counts, &a.RespectWindows, &a.Rollout, &a.PausedReason,
		&a.ReleasedStages); err != nil {
		return nil, notFound(err)
	}
	return &a, nil
}

// GetAction, aksiyonu sayaçlarıyla döner.
func (s *Store) GetAction(ctx context.Context, id string) (*Action, error) {
	return scanAction(s.pool.QueryRow(ctx, actionSelect+` WHERE a.id = $1`, id))
}

// ActionFilter, aksiyon listesi parametreleridir.
type ActionFilter struct {
	Status    string
	Kind      string
	MachineID string
	Limit     int
	Offset    int
	// Scope doluysa yalnızca kullanıcının oluşturduğu (ViewerID) veya kapsamdaki makineleri
	// hedefleyen aksiyonlar döner.
	Scope    []string
	ViewerID string
}

// ListActions, aksiyonları yeniden eskiye döner.
func (s *Store) ListActions(ctx context.Context, f ActionFilter) ([]Action, int, error) {
	args := []any{f.Status, f.Kind, f.MachineID}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	cond := `WHERE ($1 = '' OR a.status = $1) AND ($2 = '' OR a.kind = $2)
		AND ($3 = '' OR EXISTS (SELECT 1 FROM action_targets x WHERE x.action_id = a.id AND x.machine_id::text = $3))`
	if c := scopeCond("m.ad_ou", f.Scope, arg); c != "" {
		cond += ` AND (a.created_by::text = ` + arg(f.ViewerID) + ` OR EXISTS (SELECT 1 FROM action_targets x
			JOIN machines m ON m.id = x.machine_id WHERE x.action_id = a.id AND ` + c + `))`
	}
	var total int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM actions a `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, actionSelect+` `+cond+` ORDER BY a.created_at DESC LIMIT `+arg(limit)+` OFFSET `+arg(max(f.Offset, 0)),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []Action{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *a)
	}
	return out, total, rows.Err()
}

// ActionTarget, aksiyon hedefinin durumu ve sonucudur.
type ActionTarget struct {
	MachineID  string     `json:"machine_id"`
	Hostname   string     `json:"hostname"`
	OU         string     `json:"-"`
	Platform   string     `json:"os_platform"`
	Status     string     `json:"status"`
	ExitCode   *int32     `json:"exit_code"`
	Stdout     string     `json:"stdout"`
	Stderr     string     `json:"stderr"`
	Error      string     `json:"error"`
	StartedAt  *time.Time `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// Stage, kademeli dağıtımdaki aşamadır (0 = ilk); Released false ise aşama henüz açılmamıştır.
	Stage    int  `json:"stage"`
	Released bool `json:"released"`
}

// ListActionTargets, aksiyonun hedeflerini döner.
func (s *Store) ListActionTargets(ctx context.Context, actionID string) ([]ActionTarget, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.machine_id, m.hostname, m.ad_ou, m.os_platform, t.status, t.exit_code, t.stdout, t.stderr, t.error,
		       t.started_at, t.finished_at, t.updated_at, t.stage, t.released
		FROM action_targets t JOIN machines m ON m.id = t.machine_id
		WHERE t.action_id = $1 ORDER BY t.stage, lower(m.hostname)`, actionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActionTarget{}
	for rows.Next() {
		var t ActionTarget
		if err := rows.Scan(&t.MachineID, &t.Hostname, &t.OU, &t.Platform, &t.Status, &t.ExitCode, &t.Stdout, &t.Stderr,
			&t.Error, &t.StartedAt, &t.FinishedAt, &t.UpdatedAt, &t.Stage, &t.Released); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetActionStatus, aksiyonun durumunu from durumlarından birindeyse değiştirir. Aksiyon
// iptal edilir veya reddedilirse açık hedefleri de iptal edilir.
func (s *Store) SetActionStatus(ctx context.Context, id, to string, from []string, userID string, at time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var cur string
		if err := tx.QueryRow(ctx, `SELECT status FROM actions WHERE id = $1 FOR UPDATE`, id).Scan(&cur); err != nil {
			return notFound(err)
		}
		ok := false
		for _, f := range from {
			ok = ok || f == cur
		}
		if !ok {
			return ErrConflict
		}
		switch to {
		case ActionActive:
			_, err := tx.Exec(ctx, `UPDATE actions SET status = $2, approved_by = $3, approved_at = $4 WHERE id = $1`,
				id, to, nullableUUID(userID), at)
			return err
		case ActionCancelled, ActionRejected:
			if _, err := tx.Exec(ctx, `UPDATE actions SET status = $2, completed_at = $3 WHERE id = $1`, id, to, at); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE action_targets SET status = 'cancelled', finished_at = $2, updated_at = $2
				WHERE action_id = $1 AND status IN ('pending', 'downloading', 'running')`, id, at)
			return err
		}
		return errors.New("geçersiz hedef durum: " + to)
	})
}

// openJobsCond, ajana verilecek işlerin koşuludur: aksiyon etkin ve süresi dolmamış, hedefin
// aşaması açılmış, hedef bekliyor veya indiriliyor (indirme kesildiyse kaldığı yerden sürer).
// Çalışan işler yeniden verilmez; ajan yeniden başlarsa yarıda kalan işi kendisi "başarısız"
// bildirir. Bakım penceresi denetimi çağıran tarafta yapılır.
const openJobsCond = `t.machine_id = $1 AND t.status IN ('pending', 'downloading') AND t.released
	AND a.status = 'active' AND a.expires_at > $2`

// PendingJob, bekleyen iş ve pencere gereksinimidir.
type PendingJob struct {
	protocol.SignedJob
	RespectWindows bool
}

// PendingJobs, makinenin imzalı işlerini oluşturulma sırasıyla döner.
func (s *Store) PendingJobs(ctx context.Context, machineID string, now time.Time) ([]PendingJob, error) {
	rows, err := s.pool.Query(ctx, `SELECT t.payload, t.signature, a.respect_windows FROM action_targets t
		JOIN actions a ON a.id = t.action_id
		WHERE `+openJobsCond+` ORDER BY a.created_at LIMIT 20`, machineID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PendingJob{}
	for rows.Next() {
		var j PendingJob
		if err := rows.Scan(&j.Payload, &j.Signature, &j.RespectWindows); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func truncateOutput(s string) string {
	if len(s) <= protocol.MaxOutputBytes {
		return s
	}
	cut := protocol.MaxOutputBytes
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "\n…(kısaltıldı)"
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// UpdateTargetStatus, ajanın bildirdiği durumu yazar. Son duruma ulaşmış hedef değiştirilemez
// (ErrConflict); aksiyonun tüm hedefleri bittiyse aksiyon tamamlanır.
func (s *Store) UpdateTargetStatus(ctx context.Context, actionID, machineID string, r protocol.JobStatusRequest, at time.Time) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var cur string
		err := tx.QueryRow(ctx, `SELECT status FROM action_targets WHERE action_id = $1 AND machine_id = $2 FOR UPDATE`,
			actionID, machineID).Scan(&cur)
		if err != nil {
			return notFound(err)
		}
		if protocol.FinalTargetStatus(cur) {
			return ErrConflict
		}
		final := protocol.FinalTargetStatus(r.Status)
		var finished *time.Time
		if final {
			finished = &at
		}
		if _, err := tx.Exec(ctx, `
			UPDATE action_targets SET status = $3, exit_code = coalesce($4, exit_code), stdout = $5, stderr = $6, error = $7,
				started_at = CASE WHEN started_at IS NULL AND $3 <> 'pending' THEN $8 ELSE started_at END,
				finished_at = $9, updated_at = $8
			WHERE action_id = $1 AND machine_id = $2`,
			actionID, machineID, r.Status, r.ExitCode, truncateOutput(r.Stdout), truncateOutput(r.Stderr),
			truncateOutput(r.Error), at, finished); err != nil {
			return err
		}
		if !final {
			return nil
		}
		_, err = tx.Exec(ctx, `
			UPDATE actions SET status = 'completed', completed_at = $2
			WHERE id = $1 AND status = 'active'
			  AND NOT EXISTS (SELECT 1 FROM action_targets WHERE action_id = $1 AND status IN ('pending', 'downloading', 'running'))`,
			actionID, at)
		return err
	})
}

// ExpireActions, süresi dolan aksiyonların açık hedeflerini "süresi doldu" yapar ve
// hedefleri biten aksiyonları tamamlar. Etkilenen hedef sayısını döner.
func (s *Store) ExpireActions(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE action_targets t SET status = 'expired', finished_at = $1, updated_at = $1
		FROM actions a WHERE a.id = t.action_id AND a.expires_at <= $1 AND t.status IN ('pending', 'downloading')`, now)
	if err != nil {
		return 0, err
	}
	// Çalışırken süresi dolan iş için ajanın bildirimi beklenir; bir gün içinde gelmezse kapatılır.
	if _, err := s.pool.Exec(ctx, `
		UPDATE action_targets t SET status = 'failed', error = 'ajan sonuç bildirmedi', finished_at = $1, updated_at = $1
		FROM actions a WHERE a.id = t.action_id AND a.expires_at <= $1::timestamptz - interval '1 day' AND t.status = 'running'`, now); err != nil {
		return 0, err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE actions a SET status = CASE WHEN a.status = 'pending_approval' THEN 'cancelled' ELSE 'completed' END,
			completed_at = $1
		WHERE a.status IN ('active', 'pending_approval') AND (
			(a.expires_at <= $1 AND a.status = 'pending_approval') OR
			NOT EXISTS (SELECT 1 FROM action_targets t WHERE t.action_id = a.id AND t.status IN ('pending', 'downloading', 'running')))`, now)
	return tag.RowsAffected(), err
}

// DownloadGrant, ajanın paket indirmesine izin verilen aksiyon bilgisidir.
type DownloadGrant struct {
	BandwidthKbps int
	SHA256        string
	FileName      string
}

// GrantDownload, makinenin aksiyon için paketi indirebileceğini doğrular: hedef açık, aksiyon
// etkin ve paket o aksiyonun paketi olmalıdır.
func (s *Store) GrantDownload(ctx context.Context, actionID, machineID, packageID string, now time.Time) (*DownloadGrant, error) {
	var g DownloadGrant
	err := s.pool.QueryRow(ctx, `
		SELECT a.bandwidth_kbps, p.file_sha256, p.file_name
		FROM action_targets t JOIN actions a ON a.id = t.action_id JOIN packages p ON p.id = a.package_id
		WHERE t.action_id = $1 AND t.machine_id = $2 AND a.package_id = $3 AND a.status = 'active' AND a.expires_at > $4
		  AND t.status IN ('pending', 'downloading', 'running')`, actionID, machineID, packageID, now).
		Scan(&g.BandwidthKbps, &g.SHA256, &g.FileName)
	if err != nil {
		return nil, notFound(err)
	}
	return &g, nil
}

// TargetMachine, aksiyon hedefi olabilecek makinedir.
type TargetMachine struct {
	Platform string
	OU       string
}

// ActiveMachines, kimliklerden aktif olanları platform ve OU bilgisiyle döner.
func (s *Store) ActiveMachines(ctx context.Context, ids []string) (map[string]TargetMachine, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, os_platform, ad_ou FROM machines WHERE id = ANY($1::uuid[]) AND status = 'active'`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]TargetMachine{}
	for rows.Next() {
		var id string
		var t TargetMachine
		if err := rows.Scan(&id, &t.Platform, &t.OU); err != nil {
			return nil, err
		}
		out[strings.ToLower(id)] = t
	}
	return out, rows.Err()
}

// RolloutCandidate, aşaması açılmayı bekleyen kademeli aksiyondur.
type RolloutCandidate struct {
	ID        string
	CreatedAt time.Time
	Rollout   Rollout
	NextStage int
	Released  int
	Finished  int
	Succeeded int
}

// RolloutCandidates, açılmamış aşaması olan etkin kademeli aksiyonları döner.
func (s *Store) RolloutCandidates(ctx context.Context) ([]RolloutCandidate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT a.id, a.created_at, a.rollout,
		       min(t.stage) FILTER (WHERE NOT t.released),
		       count(*) FILTER (WHERE t.released),
		       count(*) FILTER (WHERE t.released AND t.status IN ('succeeded', 'failed', 'expired')),
		       count(*) FILTER (WHERE t.released AND t.status = 'succeeded')
		FROM actions a JOIN action_targets t ON t.action_id = a.id
		WHERE a.status = 'active' AND a.rollout IS NOT NULL
		GROUP BY a.id HAVING bool_or(NOT t.released)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RolloutCandidate
	for rows.Next() {
		var c RolloutCandidate
		var next int16
		if err := rows.Scan(&c.ID, &c.CreatedAt, &c.Rollout, &next, &c.Released, &c.Finished, &c.Succeeded); err != nil {
			return nil, err
		}
		c.NextStage = int(next)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ReleaseStage, aksiyonun verilen aşamaya kadarki hedeflerini açar ve duraklatmayı kaldırır.
func (s *Store) ReleaseStage(ctx context.Context, actionID string, stage int) error {
	if _, err := s.pool.Exec(ctx, `UPDATE action_targets SET released = true WHERE action_id = $1 AND stage <= $2`,
		actionID, stage); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE actions SET paused_reason = '' WHERE id = $1`, actionID)
	return err
}

// PauseRollout, kademeli dağıtımı nedeniyle birlikte duraklatır.
func (s *Store) PauseRollout(ctx context.Context, actionID, reason string) error {
	_, err := s.pool.Exec(ctx, `UPDATE actions SET paused_reason = $2 WHERE id = $1 AND paused_reason <> $2`, actionID, reason)
	return err
}

// MachineOU, makinenin OU'sunu döner.
func (s *Store) MachineOU(ctx context.Context, machineID string) (string, error) {
	var ou string
	err := s.pool.QueryRow(ctx, `SELECT ad_ou FROM machines WHERE id = $1`, machineID).Scan(&ou)
	return ou, notFound(err)
}
