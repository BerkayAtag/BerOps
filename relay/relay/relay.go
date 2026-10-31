// Package relay, şubelerde çalışan önbellekleyen dağıtım noktasıdır. Ajanların TLS
// bağlantısını sonlandırır, ajan sertifikasını iç CA'ya göre doğrular ve isteği kendi
// sertifikasıyla sunucuya iletir. Paket dosyaları SHA-256 ile doğrulanarak yerel önbellekte
// tutulur; aynı paketi isteyen şubedeki diğer makineler dosyayı WAN yerine relay'den alır.
package relay

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sunucu ile paylaşılan başlıklar (server/internal/api/relay_handlers.go).
const (
	HeaderAgentCert  = "X-Ber-Agent-Cert"
	HeaderAgentIP    = "X-Ber-Agent-Ip"
	HeaderRelayProbe = "X-Ber-Relay-Probe"
	HeaderSHA256     = "X-Ber-Sha256"
)

var (
	packagePath = regexp.MustCompile(`^/agent/v1/packages/[0-9a-fA-F-]{36}/file$`)
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config, relay ayarlarıdır.
type Config struct {
	ServerURL  string
	CA         *x509.CertPool
	Cert       tls.Certificate // relay sertifikası (sunucu + istemci kullanımı)
	CacheDir   string
	CacheBytes int64 // önbellek üst sınırı; aşılırsa en eski kullanılan dosyalar silinir
	Log        *slog.Logger
}

// Relay, HTTP işleyicisidir.
type Relay struct {
	cfg      Config
	upstream *url.URL
	client   *http.Client
	proxy    *httputil.ReverseProxy

	mu       sync.Mutex
	inflight map[string]*fetch
	// Hits ve Misses, önbellek istatistikleridir (test ve log için).
	Hits, Misses int64
}

type fetch struct {
	done chan struct{}
	err  error
}

// New, relay'i oluşturur.
func New(cfg Config) (*Relay, error) {
	u, err := url.Parse(cfg.ServerURL)
	if err != nil || u.Scheme != "https" {
		return nil, fmt.Errorf("sunucu adresi geçersiz: %q", cfg.ServerURL)
	}
	if err := os.MkdirAll(filepath.Join(cfg.CacheDir, "tmp"), 0o700); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: cfg.CA, Certificates: []tls.Certificate{cfg.Cert}, MinVersion: tls.VersionTLS12},
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
	}
	r := &Relay{cfg: cfg, upstream: u, client: &http.Client{Transport: tr}, inflight: map[string]*fetch{}}
	r.proxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(u)
			pr.Out.Host = u.Host
		},
		Transport:     tr,
		FlushInterval: -1, // uzun yoklama yanıtları beklemeden iletilir
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			cfg.Log.Warn("sunucuya iletilemedi", "hata", err)
			writeErr(w, http.StatusBadGateway, "Relay sunucuya ulaşamadı")
		},
	}
	return r, nil
}

// TLSConfig, ajanlara karşı TLS yapılandırmasıdır. İstemci sertifikası isteğe bağlıdır
// (kayıt sertifikasız yapılır) ama sunulursa iç CA'ya göre doğrulanır.
func (r *Relay) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{r.cfg.Cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    r.cfg.CA,
	}
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"code":"relay.error","message":%q}`, msg)
}

// ServeHTTP, ajan isteğini işler.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Ajanın kendi gönderdiği kimlik başlıkları asla iletilmez (sahte kimlik önlemi).
	req.Header.Del(HeaderAgentCert)
	req.Header.Del(HeaderAgentIP)
	req.Header.Del(HeaderRelayProbe)
	if req.TLS != nil && len(req.TLS.VerifiedChains) > 0 {
		req.Header.Set(HeaderAgentCert, base64.StdEncoding.EncodeToString(req.TLS.VerifiedChains[0][0].Raw))
	}
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		req.Header.Set(HeaderAgentIP, host)
	}
	if req.Method == http.MethodGet && packagePath.MatchString(req.URL.Path) && req.Header.Get(HeaderAgentCert) != "" {
		r.servePackage(w, req)
		return
	}
	r.proxy.ServeHTTP(w, req)
}

// servePackage, sunucudan yetki ve özet alır; dosya önbellekte yoksa bir kez çeker,
// doğrular ve ajana sunucunun belirlediği hız sınırıyla verir.
func (r *Relay) servePackage(w http.ResponseWriter, req *http.Request) {
	probe, err := http.NewRequestWithContext(req.Context(), http.MethodGet, r.upstream.JoinPath(req.URL.Path).String()+"?"+req.URL.RawQuery, nil)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "istek geçersiz")
		return
	}
	probe.Header.Set(HeaderAgentCert, req.Header.Get(HeaderAgentCert))
	probe.Header.Set(HeaderAgentIP, req.Header.Get(HeaderAgentIP))
	probe.Header.Set(HeaderRelayProbe, "1")
	resp, err := r.client.Do(probe)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "Relay sunucuya ulaşamadı")
		return
	}
	if resp.StatusCode != http.StatusNoContent {
		// Yetki reddi vb. olduğu gibi aktarılır.
		defer resp.Body.Close()
		for k, v := range resp.Header {
			w.Header()[k] = v
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
		return
	}
	resp.Body.Close()
	sha := resp.Header.Get(HeaderSHA256)
	size, _ := strconv.ParseInt(resp.Header.Get("X-Ber-Size"), 10, 64)
	kbps, _ := strconv.Atoi(resp.Header.Get("X-Ber-Rate-Kbps"))
	if !sha256Hex.MatchString(sha) {
		writeErr(w, http.StatusBadGateway, "Sunucu geçersiz özet döndü")
		return
	}
	path, err := r.ensure(req.Context(), sha, size)
	if err != nil {
		r.cfg.Log.Warn("paket önbelleğe alınamadı", "sha256", sha, "hata", err)
		writeErr(w, http.StatusBadGateway, "Paket relay önbelleğine alınamadı")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "önbellek okunamadı")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "önbellek okunamadı")
		return
	}
	now := time.Now()
	_ = os.Chtimes(path, now, info.ModTime()) // son erişim: LRU temizliği için
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", `"`+sha+`"`)
	h.Set("X-Ber-Relay", "hit")
	var out http.ResponseWriter = w
	if kbps > 0 {
		out = newThrottled(req.Context(), w, kbps)
	}
	http.ServeContent(out, req, sha, info.ModTime(), f)
}

// ensure, dosyanın önbellekte olmasını sağlar. Aynı dosya için eşzamanlı istekler tek
// indirmeyi bekler.
func (r *Relay) ensure(ctx context.Context, sha string, size int64) (string, error) {
	path := filepath.Join(r.cfg.CacheDir, sha)
	if st, err := os.Stat(path); err == nil && (size == 0 || st.Size() == size) {
		r.mu.Lock()
		r.Hits++
		r.mu.Unlock()
		return path, nil
	}
	r.mu.Lock()
	f, running := r.inflight[sha]
	if !running {
		f = &fetch{done: make(chan struct{})}
		r.inflight[sha] = f
		r.Misses++
	}
	r.mu.Unlock()
	if running {
		select {
		case <-f.done:
			return path, f.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	f.err = r.download(context.WithoutCancel(ctx), sha, path)
	r.mu.Lock()
	delete(r.inflight, sha)
	r.mu.Unlock()
	close(f.done)
	if f.err == nil {
		go r.evict()
	}
	return path, f.err
}

func (r *Relay) download(ctx context.Context, sha, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.upstream.JoinPath("/agent/v1/relay/files", sha).String(), nil)
	if err != nil {
		return err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sunucu %d döndü", resp.StatusCode)
	}
	tmp, err := os.CreateTemp(filepath.Join(r.cfg.CacheDir, "tmp"), sha+"-*")
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), resp.Body)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != sha {
		err = errors.New("indirilen dosyanın özeti uyuşmuyor")
	}
	if err != nil {
		os.Remove(tmp.Name())
		return err
	}
	r.cfg.Log.Info("paket önbelleğe alındı", "sha256", sha)
	return os.Rename(tmp.Name(), path)
}

// evict, önbellek üst sınırı aşılırsa en uzun süredir kullanılmayan dosyaları siler.
func (r *Relay) evict() {
	if r.cfg.CacheBytes <= 0 {
		return
	}
	entries, err := os.ReadDir(r.cfg.CacheDir)
	if err != nil {
		return
	}
	type file struct {
		path string
		size int64
		used time.Time
	}
	var files []file
	var total int64
	for _, e := range entries {
		if !sha256Hex.MatchString(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, file{filepath.Join(r.cfg.CacheDir, e.Name()), info.Size(), atime(info)})
		total += info.Size()
	}
	sort.Slice(files, func(i, j int) bool { return files[i].used.Before(files[j].used) })
	for _, f := range files {
		if total <= r.cfg.CacheBytes {
			break
		}
		if os.Remove(f.path) == nil {
			total -= f.size
			r.cfg.Log.Info("önbellekten silindi", "dosya", filepath.Base(f.path))
		}
	}
}

// atime, dosyanın son erişim zamanıdır; relay her sunumda Chtimes ile günceller, böylece
// platforma özgü erişim zamanı desteğine gerek kalmaz.
func atime(info os.FileInfo) time.Time { return info.ModTime() }

// throttled, yanıtı en fazla verilen hızda yazar.
type throttled struct {
	http.ResponseWriter
	ctx   context.Context
	rate  float64
	start time.Time
	sent  int64
}

func newThrottled(ctx context.Context, w http.ResponseWriter, kbps int) *throttled {
	return &throttled{ResponseWriter: w, ctx: ctx, rate: float64(kbps) * 1000 / 8, start: time.Now()}
}

func (t *throttled) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n := min(len(p), 16<<10)
		m, err := t.ResponseWriter.Write(p[:n])
		written += m
		t.sent += int64(m)
		if err != nil {
			return written, err
		}
		p = p[n:]
		due := time.Duration(float64(t.sent) / t.rate * float64(time.Second))
		if wait := due - time.Since(t.start); wait > 0 {
			select {
			case <-t.ctx.Done():
				return written, t.ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	return written, nil
}

// LoadCA, PEM dosyasından CA havuzu üretir.
func LoadCA(path string) (*x509.CertPool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("CA sertifikası PEM biçiminde değil")
	}
	return pool, nil
}

// HostsOf, sertifikanın ad listesini döner (log için).
func HostsOf(c tls.Certificate) string {
	if c.Leaf == nil {
		if leaf, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			c.Leaf = leaf
		}
	}
	if c.Leaf == nil {
		return ""
	}
	names := append([]string{}, c.Leaf.DNSNames...)
	for _, ip := range c.Leaf.IPAddresses {
		names = append(names, ip.String())
	}
	return strings.Join(names, ",")
}
