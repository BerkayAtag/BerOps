// Package vuln, makine envanterini CVE verisiyle eşleştirip bulguları ve risk skorlarını
// arka planda güncel tutar.
package vuln

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/cve"
	"github.com/BerkayAtag/BerOps/server/internal/store"
)

// Engine, korelasyon kuyruğudur. Envanteri değişen makineler Enqueue ile, kaynak
// eşitlemesinden sonra tüm filo RecomputeAll ile yeniden hesaplanır.
type Engine struct {
	store *store.Store
	log   *slog.Logger
	now   func() time.Time

	mu      sync.Mutex
	matcher *cve.Matcher
	pending map[string]bool
	full    bool
	wake    chan struct{}
}

// New, özel kuralları yükleyerek motoru oluşturur.
func New(ctx context.Context, st *store.Store, log *slog.Logger) (*Engine, error) {
	e := &Engine{store: st, log: log, now: time.Now, pending: map[string]bool{}, wake: make(chan struct{}, 1)}
	if err := e.ReloadRules(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

// ReloadRules, özel kuralları veritabanından yeniden okur.
func (e *Engine) ReloadRules(ctx context.Context) error {
	custom, err := e.store.ListAppRules(ctx)
	if err != nil {
		return err
	}
	m, err := cve.NewMatcher(custom)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.matcher = m
	e.mu.Unlock()
	return nil
}

// Rules, geçerli eşleme kurallarını döner (özel kurallar önce).
func (e *Engine) Rules() []cve.ProductRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.matcher.Rules()
}

// TrackedProducts, CVE eşitleyicisinin takip edeceği ürünlerdir.
func (e *Engine) TrackedProducts(context.Context) ([]cve.ProductRule, error) {
	return e.Rules(), nil
}

func (e *Engine) signal() {
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Enqueue, makineyi yeniden hesaplama kuyruğuna ekler.
func (e *Engine) Enqueue(machineID string) {
	e.mu.Lock()
	e.pending[machineID] = true
	e.mu.Unlock()
	e.signal()
}

// RecomputeAll, tüm makinelerin yeniden hesaplanmasını ister.
func (e *Engine) RecomputeAll() {
	e.mu.Lock()
	e.full = true
	e.mu.Unlock()
	e.signal()
}

// Run, kuyruğu ctx kapanana kadar işler.
func (e *Engine) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
			if err := e.Flush(ctx); err != nil && ctx.Err() == nil {
				e.log.Error("zafiyet korelasyonu başarısız", "hata", err)
			}
		}
	}
}

// Flush, bekleyen işleri şimdi ve senkron işler (testler ve Run tarafından kullanılır).
func (e *Engine) Flush(ctx context.Context) error {
	e.mu.Lock()
	full := e.full
	ids := make([]string, 0, len(e.pending))
	for id := range e.pending {
		ids = append(ids, id)
	}
	e.full, e.pending = false, map[string]bool{}
	e.mu.Unlock()

	if full {
		var err error
		if ids, err = e.store.InventoriedMachineIDs(ctx); err != nil {
			return err
		}
	}
	if len(ids) == 0 {
		return nil
	}
	start := time.Now()
	lk := cve.NewCachedLookup(e.store)
	var errs []error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := e.ComputeMachine(ctx, id, lk); err != nil {
			errs = append(errs, err)
		}
	}
	if full {
		e.log.Info("zafiyetler yeniden hesaplandı", "makine", len(ids), "süre", time.Since(start).Round(time.Millisecond).String())
	}
	return errors.Join(errs...)
}

// ComputeMachine, tek makinenin bulgularını hesaplayıp yazar. Envanteri olmayan makine atlanır.
func (e *Engine) ComputeMachine(ctx context.Context, machineID string, lk cve.Lookup) error {
	in, err := e.store.VulnInput(ctx, machineID)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	e.mu.Lock()
	m := e.matcher
	e.mu.Unlock()
	findings, err := cve.Correlate(ctx, in, m, lk)
	if err != nil {
		return err
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.CVE
	}
	meta, err := e.store.CVEMeta(ctx, ids)
	if err != nil {
		return err
	}
	scored := make([]store.ScoredFinding, len(findings))
	for i, f := range findings {
		md := meta[f.CVE]
		scored[i] = store.ScoredFinding{
			Finding:  f,
			Risk:     cve.RiskScore(md),
			Severity: cve.NormalizeSeverity(md.Severity),
			KEV:      md.KEV,
		}
	}
	return e.store.SaveMachineFindings(ctx, machineID, scored, e.now())
}
