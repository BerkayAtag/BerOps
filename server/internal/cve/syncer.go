package cve

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Kaynak adları.
const (
	FeedNVD  = "nvd"
	FeedMSRC = "msrc"
	FeedKEV  = "kev"
	FeedEPSS = "epss"
)

// AllFeeds, eşitleme sırasıdır (hızlı kaynaklar önce).
var AllFeeds = []string{FeedKEV, FeedEPSS, FeedMSRC, FeedNVD}

// Varsayılan kaynak adresleri.
const (
	DefaultNVDURL         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultMSRCUpdatesURL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
	DefaultKEVURL         = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL        = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

// nvdMaxRange, NVD API'sinin lastModStartDate/lastModEndDate arasında izin verdiği en uzun süreden
// biraz kısadır (120 gün).
const nvdMaxRange = 118 * 24 * time.Hour

// maxFeedBody, tek bir kaynak yanıtının üst sınırıdır (MSRC aylık belgeleri onlarca MB olabilir).
const maxFeedBody = 1 << 30

// FeedStore, eşitleyicinin kalıcı katmanıdır.
type FeedStore interface {
	LoadFeedState(ctx context.Context, feed string, v any) error
	BeginFeed(ctx context.Context, feed string, at time.Time) error
	FinishFeed(ctx context.Context, feed string, at time.Time, count int, dur time.Duration, state any, syncErr error) error
	UpsertRecords(ctx context.Context, recs []Record) error
	ExistingCVEs(ctx context.Context, ids []string) (map[string]bool, error)
	ReplaceKEV(ctx context.Context, entries []KEVEntry) error
	ReplaceEPSS(ctx context.Context, scoredOn time.Time, load func(add func(EPSSScore) error) error) (int, error)
}

// Syncer, CVE kaynaklarını internetten veya çevrimdışı klasörden eşitler.
type Syncer struct {
	Store FeedStore
	HTTP  *http.Client
	Log   *slog.Logger
	// Products, takip edilen CPE ürünlerini döner (yerleşik sözlük + özel kurallar).
	Products func(ctx context.Context) ([]ProductRule, error)

	NVDAPIKey  string
	MSRCMonths int
	// OfflineDir doluysa internete çıkılmaz; kaynaklar bu klasördeki dosyalardan okunur.
	OfflineDir string

	NVDURL, MSRCUpdatesURL, KEVURL, EPSSURL string

	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error

	mu      sync.Mutex
	running bool
}

// Running, eşitlemenin sürüp sürmediğini döner.
func (s *Syncer) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// ErrSyncRunning, eşitleme zaten sürerken döner.
var ErrSyncRunning = errors.New("CVE eşitlemesi zaten çalışıyor")

// Sync, istenen kaynakları (boşsa tümünü) sırayla eşitler. Bir kaynağın hatası diğerlerini
// durdurmaz; tüm hatalar birleştirilip döner.
func (s *Syncer) Sync(ctx context.Context, feeds ...string) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ErrSyncRunning
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()
	if len(feeds) == 0 {
		feeds = AllFeeds
	}
	var errs []error
	for _, f := range AllFeeds {
		if !slices.Contains(feeds, f) {
			continue
		}
		if err := s.syncFeed(ctx, f); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", f, err))
			if ctx.Err() != nil {
				break
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Syncer) syncFeed(ctx context.Context, feed string) error {
	start := s.now()
	if err := s.Store.BeginFeed(ctx, feed, start); err != nil {
		return err
	}
	var (
		count int
		state any
		err   error
	)
	switch feed {
	case FeedKEV:
		count, err = s.syncKEV(ctx)
	case FeedEPSS:
		count, err = s.syncEPSS(ctx)
	case FeedMSRC:
		var st msrcState
		_ = s.Store.LoadFeedState(ctx, feed, &st)
		count, err = s.syncMSRC(ctx, &st)
		state = st
	case FeedNVD:
		var st nvdState
		_ = s.Store.LoadFeedState(ctx, feed, &st)
		count, err = s.syncNVD(ctx, &st, start)
		state = st
	default:
		return fmt.Errorf("bilinmeyen kaynak: %s", feed)
	}
	dur := s.now().Sub(start)
	if ferr := s.Store.FinishFeed(context.WithoutCancel(ctx), feed, s.now(), count, dur, state, err); ferr != nil && err == nil {
		err = ferr
	}
	if err != nil {
		s.log().Warn("CVE kaynağı eşitlenemedi", "kaynak", feed, "hata", err, "süre", dur.Round(time.Millisecond).String())
	} else {
		s.log().Info("CVE kaynağı eşitlendi", "kaynak", feed, "kayıt", count, "süre", dur.Round(time.Millisecond).String())
	}
	return err
}

func (s *Syncer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Syncer) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (s *Syncer) sleep(ctx context.Context, d time.Duration) error {
	if s.Sleep != nil {
		return s.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func or(v, d string) string {
	if v != "" {
		return v
	}
	return d
}

// --- Okuma yardımcıları ---

type readCloser struct {
	io.Reader
	closers []io.Closer
}

func (r *readCloser) Close() error {
	var err error
	for i := len(r.closers) - 1; i >= 0; i-- {
		if e := r.closers[i].Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// wrapGzip, ".gz" uzantılı kaynakları açar ve boyutu sınırlar.
func wrapGzip(name string, rc io.ReadCloser) (io.ReadCloser, error) {
	out := &readCloser{Reader: io.LimitReader(rc, maxFeedBody), closers: []io.Closer{rc}}
	if strings.HasSuffix(strings.ToLower(name), ".gz") {
		zr, err := gzip.NewReader(out.Reader)
		if err != nil {
			rc.Close()
			return nil, err
		}
		out.Reader = io.LimitReader(zr, maxFeedBody)
		out.closers = append(out.closers, zr)
	}
	return out, nil
}

func (s *Syncer) client() *http.Client {
	if s.HTTP != nil {
		return s.HTTP
	}
	return &http.Client{Timeout: 10 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
}

// get, adresi indirir; geçici hatalarda (429, 403 hız sınırı, 5xx) bekleyip yeniden dener.
func (s *Syncer) get(ctx context.Context, rawURL string, header http.Header) (io.ReadCloser, error) {
	var lastErr error
	for attempt := range 5 {
		if attempt > 0 {
			if err := s.sleep(ctx, time.Duration(attempt)*15*time.Second); err != nil {
				return nil, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, err
		}
		for k, v := range header {
			req.Header[k] = v
		}
		req.Header.Set("User-Agent", "automation-ber-cve-sync")
		resp, err := s.client().Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			continue
		}
		if resp.StatusCode == http.StatusOK {
			u, _ := url.Parse(rawURL)
			return wrapGzip(u.Path, resp.Body)
		}
		resp.Body.Close()
		lastErr = fmt.Errorf("%s: HTTP %d", redactURL(rawURL), resp.StatusCode)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusForbidden && resp.StatusCode < 500 {
			return nil, lastErr
		}
	}
	return nil, lastErr
}

// redactURL, hata mesajlarında sorgu parametrelerini gizler.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "?"
	}
	u.RawQuery = ""
	return u.String()
}

// offlineFiles, çevrimdışı klasördeki eşleşen dosyaları ad sırasıyla döner.
func (s *Syncer) offlineFiles(patterns ...string) ([]string, error) {
	var out []string
	for _, p := range patterns {
		m, err := filepath.Glob(filepath.Join(s.OfflineDir, p))
		if err != nil {
			return nil, err
		}
		out = append(out, m...)
	}
	sort.Strings(out)
	return out, nil
}

func openOffline(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return wrapGzip(path, f)
}

// --- KEV ---

func (s *Syncer) syncKEV(ctx context.Context) (int, error) {
	var rc io.ReadCloser
	var err error
	if s.OfflineDir != "" {
		files, ferr := s.offlineFiles("known_exploited_vulnerabilities.json*", "kev.json*")
		if ferr != nil || len(files) == 0 {
			return 0, errors.New("çevrimdışı klasörde kev.json bulunamadı")
		}
		rc, err = openOffline(files[len(files)-1])
	} else {
		rc, err = s.get(ctx, or(s.KEVURL, DefaultKEVURL), nil)
	}
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	entries, err := ParseKEV(rc)
	if err != nil {
		return 0, err
	}
	return len(entries), s.Store.ReplaceKEV(ctx, entries)
}

// --- EPSS ---

func (s *Syncer) syncEPSS(ctx context.Context) (int, error) {
	var rc io.ReadCloser
	var err error
	if s.OfflineDir != "" {
		files, ferr := s.offlineFiles("epss*.csv", "epss*.csv.gz")
		if ferr != nil || len(files) == 0 {
			return 0, errors.New("çevrimdışı klasörde EPSS CSV dosyası bulunamadı")
		}
		rc, err = openOffline(files[len(files)-1])
	} else {
		rc, err = s.get(ctx, or(s.EPSSURL, DefaultEPSSURL), nil)
	}
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	scoredOn := s.now().UTC().Truncate(24 * time.Hour)
	return s.Store.ReplaceEPSS(ctx, scoredOn, func(add func(EPSSScore) error) error {
		_, _, err := ParseEPSS(rc, add)
		return err
	})
}

// --- MSRC ---

type msrcState struct {
	// Docs, işlenen aylık belgelerin son yayın zamanıdır; değişen belgeler yeniden işlenir.
	Docs map[string]time.Time `json:"docs"`
}

func (s *Syncer) syncMSRC(ctx context.Context, st *msrcState) (int, error) {
	if st.Docs == nil {
		st.Docs = map[string]time.Time{}
	}
	total := 0
	if s.OfflineDir != "" {
		files, err := s.offlineFiles("msrc/*.json", "msrc/*.json.gz")
		if err != nil {
			return 0, err
		}
		for _, f := range files {
			info, err := os.Stat(f)
			if err != nil {
				return total, err
			}
			key := filepath.Base(f)
			if prev, ok := st.Docs[key]; ok && !info.ModTime().After(prev) {
				continue
			}
			n, err := s.importMSRC(ctx, func() (io.ReadCloser, error) { return openOffline(f) })
			if err != nil {
				return total, fmt.Errorf("%s: %w", key, err)
			}
			total += n
			st.Docs[key] = info.ModTime()
		}
		return total, nil
	}

	rc, err := s.get(ctx, or(s.MSRCUpdatesURL, DefaultMSRCUpdatesURL), http.Header{"Accept": {"application/json"}})
	if err != nil {
		return 0, err
	}
	updates, err := ParseMSRCUpdates(rc)
	rc.Close()
	if err != nil {
		return 0, err
	}
	months := s.MSRCMonths
	if months <= 0 {
		months = 12
	}
	since := s.now().AddDate(0, -months, 0)
	sort.Slice(updates, func(i, j int) bool { return updates[i].InitialReleaseDate.Before(updates[j].InitialReleaseDate) })
	for _, u := range updates {
		if u.InitialReleaseDate.Before(since) || u.CvrfURL == "" {
			continue
		}
		if prev, ok := st.Docs[u.ID]; ok && !u.CurrentReleaseDate.After(prev) {
			continue
		}
		n, err := s.importMSRC(ctx, func() (io.ReadCloser, error) {
			return s.get(ctx, u.CvrfURL, http.Header{"Accept": {"application/json"}})
		})
		if err != nil {
			return total, fmt.Errorf("%s: %w", u.ID, err)
		}
		total += n
		st.Docs[u.ID] = u.CurrentReleaseDate
	}
	return total, nil
}

func (s *Syncer) importMSRC(ctx context.Context, open func() (io.ReadCloser, error)) (int, error) {
	rc, err := open()
	if err != nil {
		return 0, err
	}
	defer rc.Close()
	recs, err := ParseMSRC(rc)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(recs); i += 500 {
		if err := s.Store.UpsertRecords(ctx, recs[i:min(i+500, len(recs))]); err != nil {
			return 0, err
		}
	}
	return len(recs), nil
}

// --- NVD ---

type nvdState struct {
	// LastModified, son artımlı sorgunun bitiş zamanıdır.
	LastModified time.Time `json:"last_modified"`
	// Products, ürün bazında tam çekimin yapıldığı zamandır.
	Products map[string]time.Time `json:"products"`
}

func (s *Syncer) trackedProducts(ctx context.Context) (map[string]ProductRule, error) {
	rules, err := s.Products(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]ProductRule{}
	for _, r := range rules {
		out[r.Key()] = r
	}
	return out, nil
}

// keep, kaydın takip edilen bir ürüne ait olup olmadığını veya veritabanında zaten bulunup
// bulunmadığını döner; ilgisiz CVE'ler saklanmaz.
func (s *Syncer) filterRecords(ctx context.Context, recs []Record, tracked map[string]ProductRule) ([]Record, error) {
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	existing, err := s.Store.ExistingCVEs(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := recs[:0]
	for _, r := range recs {
		keep := existing[r.ID]
		for _, m := range r.Matches {
			if _, ok := tracked[m.Key()]; ok {
				keep = true
				break
			}
		}
		if keep {
			out = append(out, r)
		}
	}
	return out, nil
}

func (s *Syncer) syncNVD(ctx context.Context, st *nvdState, start time.Time) (int, error) {
	tracked, err := s.trackedProducts(ctx)
	if err != nil {
		return 0, err
	}
	if st.Products == nil {
		st.Products = map[string]time.Time{}
	}
	if s.OfflineDir != "" {
		return s.importNVDOffline(ctx, tracked)
	}

	total := 0
	stale := st.LastModified.IsZero() || start.Sub(st.LastModified) > nvdMaxRange
	if stale {
		st.Products = map[string]time.Time{}
	}
	keys := make([]string, 0, len(tracked))
	for k := range tracked {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if _, done := st.Products[k]; done {
			continue
		}
		q := url.Values{"virtualMatchString": {tracked[k].VirtualMatchString()}}
		n, err := s.nvdPages(ctx, q, func(recs []Record) ([]Record, error) { return recs, nil })
		total += n
		if err != nil {
			return total, fmt.Errorf("%s: %w", k, err)
		}
		st.Products[k] = start
	}
	if !stale {
		q := url.Values{
			"lastModStartDate": {nvdQueryTime(st.LastModified.Add(-time.Hour))},
			"lastModEndDate":   {nvdQueryTime(start)},
		}
		n, err := s.nvdPages(ctx, q, func(recs []Record) ([]Record, error) {
			return s.filterRecords(ctx, recs, tracked)
		})
		total += n
		if err != nil {
			return total, err
		}
	}
	// Takipten çıkan ürünlerin durumu silinir; yeniden eklenirse tam çekim yapılır.
	for k := range st.Products {
		if _, ok := tracked[k]; !ok {
			delete(st.Products, k)
		}
	}
	st.LastModified = start
	return total, nil
}

// nvdPages, sorgunun tüm sayfalarını sırayla çeker. NVD API anahtarsız 30 saniyede 5 istek,
// anahtarla 50 istek kabul eder; istekler arasında buna göre beklenir.
func (s *Syncer) nvdPages(ctx context.Context, q url.Values, filter func([]Record) ([]Record, error)) (int, error) {
	delay := 6500 * time.Millisecond
	header := http.Header{}
	if s.NVDAPIKey != "" {
		delay = 700 * time.Millisecond
		header.Set("apiKey", s.NVDAPIKey)
	}
	const perPage = 2000
	total, index := 0, 0
	for {
		q.Set("resultsPerPage", itoa(perPage))
		q.Set("startIndex", itoa(index))
		rc, err := s.get(ctx, or(s.NVDURL, DefaultNVDURL)+"?"+q.Encode(), header)
		if err != nil {
			return total, err
		}
		page, recs, err := ParseNVD(rc)
		rc.Close()
		if err != nil {
			return total, err
		}
		recs, err = filter(recs)
		if err != nil {
			return total, err
		}
		if len(recs) > 0 {
			if err := s.Store.UpsertRecords(ctx, recs); err != nil {
				return total, err
			}
		}
		total += len(recs)
		index += len(page.Vulnerabilities)
		if len(page.Vulnerabilities) == 0 || index >= page.TotalResults {
			return total, nil
		}
		if err := s.sleep(ctx, delay); err != nil {
			return total, err
		}
	}
}

func (s *Syncer) importNVDOffline(ctx context.Context, tracked map[string]ProductRule) (int, error) {
	files, err := s.offlineFiles("nvd/*.json", "nvd/*.json.gz")
	if err != nil {
		return 0, err
	}
	if len(files) == 0 {
		return 0, errors.New("çevrimdışı klasörde nvd/*.json dosyası bulunamadı")
	}
	total := 0
	for _, f := range files {
		rc, err := openOffline(f)
		if err != nil {
			return total, err
		}
		_, recs, err := ParseNVD(rc)
		rc.Close()
		if err != nil {
			return total, fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		recs, err = s.filterRecords(ctx, recs, tracked)
		if err != nil {
			return total, err
		}
		for i := 0; i < len(recs); i += 1000 {
			if err := s.Store.UpsertRecords(ctx, recs[i:min(i+1000, len(recs))]); err != nil {
				return total, err
			}
		}
		total += len(recs)
	}
	return total, nil
}
