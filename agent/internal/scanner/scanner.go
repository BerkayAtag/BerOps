// Package scanner, envanter taramalarını zamanlar ve sonuçları sunucuyla eşitler.
//
// Model: Toplanan her bölüm yerel önbelleğe (cache) yazılır. Sunucunun elindeki bölüm
// özetleri (uploaded) ayrıca tutulur. Eşitleme, önbellekteki özeti sunucudakinden farklı
// olan bölümleri gönderir; böylece delta yükleme, başarısız yüklemelerin yeniden denenmesi
// ve sunucunun "tam envanter gönder" isteği aynı mekanizmayla karşılanır.
package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/BerkayAtag/BerOps/agent/internal/inventory"
	"github.com/BerkayAtag/BerOps/shared/protocol"
)

const (
	cacheFile = "cache.json"
	stateFile = "state.json"
	cabFile   = "wsusscn2.cab"

	firstScanMaxDelay = 5 * time.Minute
	deferStep         = 15 * time.Minute
	maxDefer          = 4 * time.Hour
	retryDelay        = 10 * time.Minute
	userIdleThreshold = 5 * time.Minute
)

// Client, envanterin gönderildiği sunucu istemcisidir.
type Client interface {
	UploadInventory(ctx context.Context, r *protocol.InventoryReport) error
	DownloadWSUSCab(ctx context.Context, dest string) error
}

// Cache, en son toplanan bölümlerdir.
type Cache struct {
	OS               *protocol.OSInventory     `json:"os,omitempty"`
	InstalledPatches []protocol.InstalledPatch `json:"installed_patches,omitempty"`
	MissingPatches   []protocol.MissingPatch   `json:"missing_patches,omitempty"`
	MissingScan      *protocol.MissingScanInfo `json:"missing_scan,omitempty"`
	Apps             []protocol.App            `json:"apps,omitempty"`
	Hashes           map[string]string         `json:"hashes"`
	CollectedAt      time.Time                 `json:"collected_at"`
	DurationMs       int64                     `json:"duration_ms"`
	Errors           []string                  `json:"errors,omitempty"`
}

// State, zamanlama ve eşitleme durumudur.
type State struct {
	LastFullAt         time.Time         `json:"last_full_at"`
	LastDeltaAt        time.Time         `json:"last_delta_at"`
	NextFullAt         time.Time         `json:"next_full_at"`
	NextDeltaAt        time.Time         `json:"next_delta_at"`
	Uploaded           map[string]string `json:"uploaded"`
	HandledScanRequest time.Time         `json:"handled_scan_request"`
	SyncPending        bool              `json:"sync_pending"`
	NextSyncAt         time.Time         `json:"next_sync_at"`
	DeferredSince      *time.Time        `json:"deferred_since,omitempty"`
}

// Scanner, envanter taramalarını yürütür.
type Scanner struct {
	Dir      string
	Platform string
	Client   Client
	Log      *slog.Logger
	Collect  func(ctx context.Context, opts inventory.Options) *inventory.Snapshot

	OnBattery  func() (bool, error)
	UserActive func(time.Duration) (bool, error)
	// FirstScanMaxDelay, kayıttan sonraki ilk tam taramanın en uzun rastgele gecikmesidir.
	FirstScanMaxDelay time.Duration

	now func() time.Time
	rnd func() float64

	mu         sync.Mutex
	settings   protocol.AgentSettings
	state      State
	cache      *Cache
	scanReq    *time.Time
	resend     bool
	wake       chan struct{}
	loaded     bool
	scanActive bool
}

// New, varsayılan bağımlılıklarla tarayıcı oluşturur.
func New(dir, platform string, client Client, log *slog.Logger) *Scanner {
	return &Scanner{
		Dir: dir, Platform: platform, Client: client, Log: log,
		Collect:           inventory.Collect,
		FirstScanMaxDelay: firstScanMaxDelay,
		now:               time.Now,
		rnd:               rand.Float64,
		settings:          protocol.DefaultAgentSettings(),
		wake:              make(chan struct{}, 1),
	}
}

// Load, kayıtlı durumu ve önbelleği okur; ilk çalıştırmada ilk tam taramayı planlar.
func (s *Scanner) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if b, err := os.ReadFile(filepath.Join(s.Dir, stateFile)); err == nil {
		_ = json.Unmarshal(b, &s.state)
	}
	if b, err := os.ReadFile(filepath.Join(s.Dir, cacheFile)); err == nil {
		var c Cache
		if json.Unmarshal(b, &c) == nil {
			s.cache = &c
		}
	}
	if s.state.Uploaded == nil {
		s.state.Uploaded = map[string]string{}
	}
	now := s.now()
	if s.state.NextFullAt.IsZero() {
		if s.state.LastFullAt.IsZero() {
			// Kayıttan hemen sonra ilk envanter kısa ve rastgele bir gecikmeyle alınır.
			s.state.NextFullAt = now.Add(time.Duration(s.rnd() * float64(s.FirstScanMaxDelay)))
		} else {
			s.state.NextFullAt = s.nextAfter(s.state.LastFullAt, s.settings.FullScanIntervalHours)
		}
	}
	if s.state.NextDeltaAt.IsZero() {
		s.state.NextDeltaAt = s.nextAfter(maxTime(s.state.LastDeltaAt, s.state.LastFullAt, now), s.settings.DeltaScanIntervalHours)
	}
	s.loaded = true
	return nil
}

func maxTime(ts ...time.Time) time.Time {
	var m time.Time
	for _, t := range ts {
		if t.After(m) {
			m = t
		}
	}
	return m
}

// nextAfter, from + saat aralığı ± %10 jitter'dır.
func (s *Scanner) nextAfter(from time.Time, hours int) time.Time {
	d := time.Duration(hours) * time.Hour
	return from.Add(d + time.Duration((s.rnd()*2-1)*0.1*float64(d)))
}

// UploadedHashes, sunucunun sahip olduğu bölüm özetleridir (heartbeat'e eklenir).
func (s *Scanner) UploadedHashes() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.state.Uploaded) == 0 {
		return nil
	}
	out := make(map[string]string, len(s.state.Uploaded))
	for k, v := range s.state.Uploaded {
		out[k] = v
	}
	return out
}

// ApplyHeartbeat, heartbeat yanıtındaki ayarları ve talimatları uygular.
func (s *Scanner) ApplyHeartbeat(resp *protocol.HeartbeatResponse) {
	s.mu.Lock()
	changed := false
	if resp.Settings != nil && *resp.Settings != s.settings && resp.Settings.Validate() == nil {
		old := s.settings
		s.settings = *resp.Settings
		if old.FullScanIntervalHours != s.settings.FullScanIntervalHours && !s.state.LastFullAt.IsZero() {
			s.state.NextFullAt = s.nextAfter(s.state.LastFullAt, s.settings.FullScanIntervalHours)
		}
		if old.DeltaScanIntervalHours != s.settings.DeltaScanIntervalHours {
			s.state.NextDeltaAt = s.nextAfter(maxTime(s.state.LastDeltaAt, s.state.LastFullAt), s.settings.DeltaScanIntervalHours)
		}
		changed = true
	}
	if resp.ScanRequestedAt != nil && resp.ScanRequestedAt.After(s.state.HandledScanRequest) && !s.scanActive {
		t := *resp.ScanRequestedAt
		s.scanReq = &t
		changed = true
	}
	if resp.RequestFullInventory && !s.scanActive {
		s.resend = true
		changed = true
	}
	s.mu.Unlock()
	if changed {
		s.nudge()
	}
}

// RequestFullScan, eksik yamalar dahil tam taramayı hemen başlatır (ör. yama kurulumundan sonra).
func (s *Scanner) RequestFullScan() {
	s.mu.Lock()
	s.state.NextFullAt = s.now()
	s.mu.Unlock()
	s.nudge()
}

// RequestDeltaScan, değişiklik taramasını hemen yaptırır (ör. paket kurulduktan sonra
// konsolun yeni sürümü görmesi için).
func (s *Scanner) RequestDeltaScan() {
	s.mu.Lock()
	s.state.NextDeltaAt = s.now()
	s.mu.Unlock()
	s.nudge()
}

func (s *Scanner) nudge() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Run, bağlam iptal edilene kadar zamanlanmış işleri yürütür.
func (s *Scanner) Run(ctx context.Context) {
	if !s.loaded {
		if err := s.Load(); err != nil {
			s.Log.Error("envanter durumu yüklenemedi", "hata", err)
		}
	}
	for {
		wait := s.Step(ctx)
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-s.wake:
			t.Stop()
		case <-t.C:
		}
	}
}

// Step, vadesi gelen işi yapar ve bir sonraki işe kadar beklenecek süreyi döner.
func (s *Scanner) Step(ctx context.Context) time.Duration {
	now := s.now()
	s.mu.Lock()
	scanReq, resend := s.scanReq, s.resend
	st := s.state
	set := s.settings
	s.mu.Unlock()

	switch {
	case scanReq != nil:
		s.Log.Info("konsoldan tarama istendi", "istek", scanReq.Format(time.RFC3339))
		s.scan(ctx, true, set)
		s.mu.Lock()
		s.state.HandledScanRequest = *scanReq
		s.scanReq = nil
		s.mu.Unlock()
		s.persist()
	case resend:
		s.mu.Lock()
		s.resend = false
		hasCache := s.cache != nil
		s.mu.Unlock()
		if hasCache {
			s.Log.Info("sunucu tam envanter istedi; önbellekteki envanter gönderiliyor")
			s.sync(ctx, true)
		} else {
			s.scan(ctx, true, set)
		}
	case !now.Before(st.NextFullAt):
		if s.shouldDefer(now, set) {
			break
		}
		s.scan(ctx, true, set)
	case !now.Before(st.NextDeltaAt):
		if s.shouldDefer(now, set) {
			break
		}
		s.scan(ctx, false, set)
	case st.SyncPending && !now.Before(st.NextSyncAt):
		s.sync(ctx, false)
	}
	return s.untilNext()
}

func (s *Scanner) untilNext() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.state.NextFullAt
	if s.state.NextDeltaAt.Before(next) {
		next = s.state.NextDeltaAt
	}
	if s.state.SyncPending && s.state.NextSyncAt.Before(next) {
		next = s.state.NextSyncAt
	}
	if s.state.DeferredSince != nil {
		if d := s.now().Add(deferStep); d.Before(next) || !s.now().Before(next) {
			next = d
		}
	}
	d := next.Sub(s.now())
	if d < time.Second {
		d = time.Second
	}
	return d
}

// shouldDefer, zamanlanmış taramanın pil veya kullanıcı etkinliği nedeniyle ertelenip
// ertelenmeyeceğine karar verir. Erteleme en fazla maxDefer sürer; sonra tarama yapılır.
func (s *Scanner) shouldDefer(now time.Time, set protocol.AgentSettings) bool {
	reason := ""
	if set.DeferOnBattery && s.OnBattery != nil {
		if on, err := s.OnBattery(); err == nil && on {
			reason = "pil"
		}
	}
	if reason == "" && set.DeferWhenUserActive && s.UserActive != nil {
		if active, err := s.UserActive(userIdleThreshold); err == nil && active {
			reason = "kullanıcı etkin"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if reason == "" {
		s.state.DeferredSince = nil
		return false
	}
	if s.state.DeferredSince == nil {
		t := now
		s.state.DeferredSince = &t
	}
	if now.Sub(*s.state.DeferredSince) >= maxDefer {
		s.Log.Info("tarama en fazla erteleme süresine ulaştı; yine de yapılıyor", "neden", reason)
		s.state.DeferredSince = nil
		return false
	}
	s.Log.Debug("tarama ertelendi", "neden", reason)
	return true
}

// scan, envanteri toplar, önbelleği günceller ve sunucuyla eşitler.
func (s *Scanner) scan(ctx context.Context, full bool, set protocol.AgentSettings) {
	s.mu.Lock()
	s.scanActive = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.scanActive = false
		s.mu.Unlock()
	}()

	opts := inventory.Options{CPULimitPercent: set.ScanCPULimitPercent, IncludeMissing: full}
	if full && s.Platform == protocol.PlatformWindows && set.WindowsUpdateSource == protocol.ScanSourceOffline {
		dest := filepath.Join(s.Dir, cabFile)
		if err := s.Client.DownloadWSUSCab(ctx, dest); err != nil {
			s.Log.Warn("wsusscn2.cab indirilemedi; eksik yama taraması atlanıyor", "hata", err)
			opts.IncludeMissing = false
		} else {
			opts.WSUSCabPath = dest
		}
	}

	kind := "değişiklik"
	if full {
		kind = "tam"
	}
	s.Log.Info("envanter taraması başladı", "tür", kind)
	snap := s.Collect(ctx, opts)
	if ctx.Err() != nil {
		return
	}
	s.Log.Info("envanter taraması bitti", "tür", kind, "süre", snap.Duration.Round(time.Millisecond).String(),
		"uygulama", len(snap.Apps), "kurulu_yama", len(snap.InstalledPatches), "eksik_yama", len(snap.MissingPatches),
		"hata", len(snap.Errors))
	for _, e := range snap.Errors {
		s.Log.Warn("tarama hatası", "ayrıntı", e)
	}

	now := s.now()
	s.mu.Lock()
	c := s.cache
	if c == nil {
		c = &Cache{Hashes: map[string]string{}}
	}
	if snap.Collected[protocol.SectionOS] {
		c.OS = snap.OS
		c.Hashes[protocol.SectionOS] = protocol.HashSection(snap.OS)
	}
	if snap.Collected[protocol.SectionInstalledPatches] {
		c.InstalledPatches = snap.InstalledPatches
		c.Hashes[protocol.SectionInstalledPatches] = protocol.HashSection(snap.InstalledPatches)
	}
	if snap.Collected[protocol.SectionMissingPatches] {
		c.MissingPatches = snap.MissingPatches
		c.MissingScan = snap.MissingScan
		c.Hashes[protocol.SectionMissingPatches] = protocol.HashSection(snap.MissingPatches)
	}
	if snap.Collected[protocol.SectionApps] {
		c.Apps = snap.Apps
		c.Hashes[protocol.SectionApps] = protocol.HashSection(snap.Apps)
	}
	c.CollectedAt, c.DurationMs, c.Errors = now.UTC(), snap.Duration.Milliseconds(), snap.Errors
	s.cache = c
	if full {
		s.state.LastFullAt = now
		s.state.NextFullAt = s.nextAfter(now, s.settings.FullScanIntervalHours)
	}
	s.state.LastDeltaAt = now
	s.state.NextDeltaAt = s.nextAfter(now, s.settings.DeltaScanIntervalHours)
	s.state.DeferredSince = nil
	s.mu.Unlock()

	s.sync(ctx, full)
}

// sync, önbellekte olup sunucudakinden farklı olan bölümleri gönderir. full ise
// önbellekteki tüm bölümler gönderilir ve sunucu kendi özetlerini bunlarla değiştirir.
func (s *Scanner) sync(ctx context.Context, full bool) {
	s.mu.Lock()
	c := s.cache
	if c == nil {
		s.mu.Unlock()
		return
	}
	rep := &protocol.InventoryReport{
		Full: full, CollectedAt: c.CollectedAt, ScanDurationMs: c.DurationMs, Errors: c.Errors,
		Hashes: map[string]string{},
	}
	for _, sec := range protocol.AllSections {
		h, ok := c.Hashes[sec]
		if !ok {
			continue
		}
		rep.Hashes[sec] = h
		if !full && s.state.Uploaded[sec] == h {
			continue
		}
		rep.Included = append(rep.Included, sec)
		switch sec {
		case protocol.SectionOS:
			rep.OS = c.OS
		case protocol.SectionInstalledPatches:
			rep.InstalledPatches = nonNilPatches(c.InstalledPatches)
		case protocol.SectionMissingPatches:
			rep.MissingPatches, rep.MissingScan = nonNilMissing(c.MissingPatches), c.MissingScan
		case protocol.SectionApps:
			rep.Apps = nonNilApps(c.Apps)
		}
	}
	s.mu.Unlock()

	if len(rep.Included) == 0 {
		s.mu.Lock()
		s.state.SyncPending = false
		s.mu.Unlock()
		s.persist()
		s.Log.Debug("envanter değişmedi; gönderilecek bölüm yok")
		return
	}

	err := s.Client.UploadInventory(ctx, rep)
	s.mu.Lock()
	if err != nil {
		s.state.SyncPending = true
		s.state.NextSyncAt = s.now().Add(retryDelay)
		s.mu.Unlock()
		s.persist()
		if !errors.Is(err, context.Canceled) {
			s.Log.Warn("envanter gönderilemedi; yeniden denenecek", "hata", err, "bölümler", rep.Included)
		}
		return
	}
	if full {
		s.state.Uploaded = map[string]string{}
	}
	for _, sec := range rep.Included {
		s.state.Uploaded[sec] = rep.Hashes[sec]
	}
	s.state.SyncPending = false
	s.mu.Unlock()
	s.persist()
	s.Log.Info("envanter gönderildi", "tam", full, "bölümler", rep.Included)
}

func nonNilApps(a []protocol.App) []protocol.App {
	if a == nil {
		return []protocol.App{}
	}
	return a
}

func nonNilPatches(a []protocol.InstalledPatch) []protocol.InstalledPatch {
	if a == nil {
		return []protocol.InstalledPatch{}
	}
	return a
}

func nonNilMissing(a []protocol.MissingPatch) []protocol.MissingPatch {
	if a == nil {
		return []protocol.MissingPatch{}
	}
	return a
}

// persist, durumu ve önbelleği diske yazar (ajan yeniden başladığında tekrar tarama
// yapmadan eşitlemeye devam edebilmesi için).
func (s *Scanner) persist() {
	s.mu.Lock()
	st, err1 := json.Marshal(s.state)
	var cache []byte
	var err2 error
	if s.cache != nil {
		cache, err2 = json.Marshal(s.cache)
	}
	s.mu.Unlock()
	if err1 == nil {
		_ = writeAtomic(filepath.Join(s.Dir, stateFile), st)
	}
	if err2 == nil && cache != nil {
		_ = writeAtomic(filepath.Join(s.Dir, cacheFile), cache)
	}
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
