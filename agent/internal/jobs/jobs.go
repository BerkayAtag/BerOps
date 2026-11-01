// Package jobs, sunucunun gönderdiği imzalı işleri (paket dağıtımı, komut çalıştırma)
// doğrular, paketi indirir, çalıştırır ve sonucu bildirir.
package jobs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// Client, iş uç noktalarına erişimdir.
type Client interface {
	Jobs(ctx context.Context) ([]protocol.SignedJob, error)
	JobStatus(ctx context.Context, jobID string, req protocol.JobStatusRequest) error
	DownloadPackage(ctx context.Context, packageID, actionID, dest string) error
}

// Spec, çalıştırılacak komuttur.
type Spec struct {
	Shell   string
	Command string
	Timeout time.Duration
	// WorkDir, betiğin yazılacağı ve çalıştırılacağı dizindir.
	WorkDir string
	// File, indirilen paket dosyasıdır (dağıtım işlerinde).
	File      string
	Installer string
}

// Result, komutun sonucudur.
type Result struct {
	ExitCode int
	Stdout   string
	Stderr   string
	// Err, komut başlatılamadıysa veya zaman aşımına uğradıysa doludur.
	Err error
}

// journalEntry, işlenen işin kaydıdır. Aynı iş (yeniden gönderim veya tekrar oynatma) ikinci
// kez çalıştırılmaz; bildirilemeyen son durum sonraki turda yeniden bildirilir.
type journalEntry struct {
	// JobID, sonucun bildirildiği aksiyon kimliğidir (anahtar, yeniden denemede deneme numarası içerir).
	JobID    string                     `json:"job_id,omitempty"`
	Status   string                     `json:"status"`
	Report   *protocol.JobStatusRequest `json:"report,omitempty"`
	Reported bool                       `json:"reported"`
	At       time.Time                  `json:"at"`
}

const journalFile = "journal.json"

// journalTTL, tamamlanan işlerin günlükte tutulma süresidir (işler en fazla 30 gün geçerlidir).
const journalTTL = 31 * 24 * time.Hour

// Runner, iş kuyruğunu işler.
type Runner struct {
	Dir       string
	Client    Client
	Log       *slog.Logger
	MachineID string
	// Key, sabitlenmiş aksiyon imza anahtarıdır; nil ise hiçbir iş çalıştırılmaz.
	Key func() ed25519.PublicKey
	// Exec, komutu çalıştırır (testlerde değiştirilebilir).
	Exec func(ctx context.Context, s Spec) Result
	// OnFinished, başarıyla biten ve yeniden tarama isteyen işten sonra çağrılır.
	OnFinished func(j *protocol.Job)
	// LogFile, ajanın günlük dosyasıdır; collect_logs işi bu dosyanın son kısmını döndürür.
	LogFile string

	now     func() time.Time
	mu      sync.Mutex
	journal map[string]*journalEntry
	wake    chan struct{}
}

// New, varsayılan yürütücüyle bir Runner üretir.
func New(dir string, c Client, log *slog.Logger, machineID string, key func() ed25519.PublicKey) *Runner {
	// Betik yolu ve çalışma dizini birlikte kullanıldığından dizin mutlak olmalıdır
	// (geliştirmede ajan göreli -data-dir ile çalıştırılabilir).
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return &Runner{Dir: dir, Client: c, Log: log, MachineID: machineID, Key: key, Exec: Execute,
		now: time.Now, wake: make(chan struct{}, 1)}
}

// Notify, heartbeat'te bekleyen iş bildirildiğinde çağrılır.
func (r *Runner) Notify(pending int) {
	if pending <= 0 {
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Runner) load() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.journal = map[string]*journalEntry{}
	b, err := os.ReadFile(filepath.Join(r.Dir, journalFile))
	if err == nil {
		_ = json.Unmarshal(b, &r.journal)
	}
	// Ajan iş çalışırken durduysa sonuç bilinemez; iş başarısız sayılır ve tekrar çalıştırılmaz
	// (yükleyicinin iki kez çalışması daha büyük sorun yaratabilir).
	for _, e := range r.journal {
		if !protocol.FinalTargetStatus(e.Status) {
			e.Status = protocol.TargetFailed
			e.Report = &protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: "ajan iş sürerken yeniden başladı"}
			e.Reported = false
		}
	}
}

func (r *Runner) save() {
	r.mu.Lock()
	cutoff := r.now().Add(-journalTTL)
	for id, e := range r.journal {
		if e.At.Before(cutoff) {
			delete(r.journal, id)
		}
	}
	b, err := json.MarshalIndent(r.journal, "", "  ")
	r.mu.Unlock()
	if err != nil {
		return
	}
	if err := os.MkdirAll(r.Dir, 0o700); err == nil {
		tmp := filepath.Join(r.Dir, journalFile+".tmp")
		if os.WriteFile(tmp, b, 0o600) == nil {
			_ = os.Rename(tmp, filepath.Join(r.Dir, journalFile))
		}
	}
}

// journalKey, işin günlük anahtarıdır: ilk denemede aksiyon kimliği, yeniden denemelerde
// kimlik#deneme. Böylece yeni deneme eski sonuç yüzünden atlanmaz, aynı deneme ise tekrar
// çalıştırılmaz.
func journalKey(job *protocol.Job) string {
	if job.Attempt > 0 {
		return fmt.Sprintf("%s#%d", job.ID, job.Attempt)
	}
	return job.ID
}

func (r *Runner) setJournal(job *protocol.Job, status string, report *protocol.JobStatusRequest, reported bool) {
	r.mu.Lock()
	r.journal[journalKey(job)] = &journalEntry{JobID: job.ID, Status: status, Report: report, Reported: reported, At: r.now()}
	r.mu.Unlock()
	r.save()
}

// Run, bağlam iptal edilene kadar işleri işler. İlk turda bildirilemeyen sonuçlar gönderilir.
func (r *Runner) Run(ctx context.Context) {
	r.load()
	r.Process(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.wake:
			r.Process(ctx)
		}
	}
}

// Process, bildirilmemiş sonuçları gönderir ve bekleyen işleri sırayla çalıştırır.
func (r *Runner) Process(ctx context.Context) {
	if r.journal == nil {
		r.load()
	}
	r.flushReports(ctx)
	key := r.Key()
	if len(key) != ed25519.PublicKeySize {
		r.Log.Warn("aksiyon imza anahtarı yok; işler çalıştırılmayacak")
		return
	}
	list, err := r.Client.Jobs(ctx)
	if err != nil {
		r.Log.Warn("işler alınamadı", "hata", err)
		return
	}
	for _, sj := range list {
		if ctx.Err() != nil {
			return
		}
		job, err := sj.Verify(key, r.MachineID, r.now())
		if err != nil {
			// İmzasız/geçersiz iş çalıştırılmaz; kimliği güvenilir olmadığından durum da bildirilmez.
			r.Log.Error("iş reddedildi", "hata", err)
			continue
		}
		r.mu.Lock()
		prev := r.journal[journalKey(job)]
		r.mu.Unlock()
		if prev != nil && protocol.FinalTargetStatus(prev.Status) {
			// Daha önce sonuçlanmış iş tekrar gelirse yeniden çalıştırılmaz; sonuç tekrar bildirilir.
			if prev.Report != nil {
				_ = r.report(ctx, job.ID, *prev.Report)
			}
			continue
		}
		r.run(ctx, job)
	}
}

func (r *Runner) flushReports(ctx context.Context) {
	r.mu.Lock()
	var keys []string
	for key, e := range r.journal {
		if !e.Reported && e.Report != nil && protocol.FinalTargetStatus(e.Status) {
			keys = append(keys, key)
		}
	}
	r.mu.Unlock()
	for _, key := range keys {
		r.mu.Lock()
		e := r.journal[key]
		rep, id := *e.Report, e.JobID
		r.mu.Unlock()
		if id == "" {
			id = key // eski sürümün günlük kaydı
		}
		if r.report(ctx, id, rep) == nil {
			r.mu.Lock()
			r.journal[key].Reported = true
			r.mu.Unlock()
			r.save()
		}
	}
}

func (r *Runner) report(ctx context.Context, id string, req protocol.JobStatusRequest) error {
	err := r.Client.JobStatus(ctx, id, req)
	if err != nil {
		var conflict interface{ StatusCode() int }
		if errors.As(err, &conflict) && (conflict.StatusCode() == 409 || conflict.StatusCode() == 404) {
			// İş sunucuda iptal edilmiş veya zaten sonuçlanmış: tekrar denemenin anlamı yok.
			return nil
		}
		r.Log.Warn("iş durumu bildirilemedi", "iş", id, "hata", err)
	}
	return err
}

func (r *Runner) finish(ctx context.Context, job *protocol.Job, rep protocol.JobStatusRequest) {
	rep.Stdout, rep.Stderr = clip(rep.Stdout), clip(rep.Stderr)
	r.setJournal(job, rep.Status, &rep, false)
	if r.report(ctx, job.ID, rep) == nil {
		r.setJournal(job, rep.Status, &rep, true)
	}
	r.Log.Info("iş tamamlandı", "iş", job.ID, "tür", job.Kind, "durum", rep.Status)
	if rep.Status == protocol.TargetSucceeded && job.RescanAfter && r.OnFinished != nil {
		r.OnFinished(job)
	}
}

func (r *Runner) run(ctx context.Context, job *protocol.Job) {
	r.Log.Info("iş başlıyor", "iş", job.ID, "tür", job.Kind)
	work := filepath.Join(r.Dir, "work", job.ID)
	if err := os.MkdirAll(work, 0o700); err != nil {
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: err.Error()})
		return
	}
	defer os.RemoveAll(work)

	if job.Kind == protocol.JobCollectLogs {
		// Komut çalıştırılmaz: ajanın kendi günlüğünün son kısmı sonuç olarak gönderilir.
		out, err := tailFile(r.LogFile, protocol.MaxOutputBytes-1024)
		if err != nil {
			r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: "günlük okunamadı: " + err.Error()})
			return
		}
		zero := 0
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetSucceeded, ExitCode: &zero, Stdout: out})
		return
	}

	spec := Spec{Shell: job.Shell, Command: job.Command, Timeout: time.Duration(job.TimeoutSeconds) * time.Second, WorkDir: work}
	if job.Kind == protocol.JobDeployPackage {
		r.setJournal(job, protocol.TargetDownloading, nil, false)
		_ = r.report(ctx, job.ID, protocol.JobStatusRequest{Status: protocol.TargetDownloading})
		file, err := r.fetch(ctx, job)
		if err != nil {
			if ctx.Err() != nil {
				// Ajan durduruluyor: iş sunucuda "indiriliyor" kalır ve sonraki açılışta sürdürülür.
				r.mu.Lock()
				delete(r.journal, journalKey(job))
				r.mu.Unlock()
				r.save()
				return
			}
			r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: "indirme: " + err.Error()})
			return
		}
		spec.File, spec.Installer = file, job.Package.Installer
		spec.Command = strings.ReplaceAll(spec.Command, protocol.FilePlaceholder, file)
	}

	r.setJournal(job, protocol.TargetRunning, nil, false)
	_ = r.report(ctx, job.ID, protocol.JobStatusRequest{Status: protocol.TargetRunning})
	res := r.Exec(ctx, spec)
	rep := protocol.JobStatusRequest{Status: protocol.TargetFailed, Stdout: res.Stdout, Stderr: res.Stderr}
	if res.Err != nil {
		rep.Error = res.Err.Error()
	}
	if res.Err == nil || res.ExitCode != 0 {
		code := res.ExitCode
		rep.ExitCode = &code
	}
	codes := job.SuccessCodes
	if len(codes) == 0 {
		codes = []int{0}
	}
	if res.Err == nil && slices.Contains(codes, res.ExitCode) {
		rep.Status = protocol.TargetSucceeded
	}
	if job.Package != nil && rep.Status == protocol.TargetSucceeded {
		_ = os.RemoveAll(filepath.Join(r.Dir, "cache", job.Package.SHA256))
	}
	r.finish(context.WithoutCancel(ctx), job, rep)
}

// fetch, paketi önbelleğe indirir (kesilirse kaldığı yerden sürer) ve boyutunu ve SHA-256
// özetini imzalı iş tanımıyla karşılaştırır. Dosya özgün adıyla ayrı bir dizine konur.
func (r *Runner) fetch(ctx context.Context, job *protocol.Job) (string, error) {
	p := job.Package
	dir := filepath.Join(r.Dir, "cache", p.SHA256)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Base(strings.ReplaceAll(p.FileName, `\`, "/"))
	if name == "." || name == "/" || name == "" {
		name = "paket"
	}
	dest := filepath.Join(dir, name)
	if ok, _ := verifyFile(dest, p.Size, p.SHA256); ok {
		return dest, nil
	}
	_ = os.Remove(dest)
	if err := r.Client.DownloadPackage(ctx, p.ID, job.ID, dest); err != nil {
		return "", err
	}
	ok, err := verifyFile(dest, p.Size, p.SHA256)
	if err != nil {
		return "", err
	}
	if !ok {
		_ = os.Remove(dest)
		return "", errors.New("dosya özeti imzalı iş tanımıyla uyuşmuyor; dosya silindi")
	}
	return dest, nil
}

func verifyFile(path string, size int64, sha string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() != size {
		return false, err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}
	return hex.EncodeToString(h.Sum(nil)) == sha, nil
}

// clip, çıktıyı geçerli UTF-8'e çevirir ve üst sınırı uygular.
// tailFile, dosyanın son max baytını satır başından başlayarak döner.
func tailFile(path string, max int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	start := info.Size() - int64(max)
	if start < 0 {
		start = 0
	}
	buf := make([]byte, info.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if start > 0 {
		// Yarım kalan ilk satır atlanır.
		if i := bytes.IndexByte(buf, '\n'); i >= 0 {
			buf = buf[i+1:]
		}
	}
	return string(buf), nil
}

func clip(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > protocol.MaxOutputBytes {
		cut := protocol.MaxOutputBytes
		for cut > 0 && s[cut]&0xC0 == 0x80 {
			cut--
		}
		s = s[:cut] + fmt.Sprintf("\n…(%d bayt kısaltıldı)", len(s)-cut)
	}
	return s
}

// limitedBuffer, en fazla limit bayt tutar; fazlası atılır ama sayılır.
type limitedBuffer struct {
	mu      sync.Mutex
	buf     []byte
	limit   int
	dropped int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	room := b.limit - len(b.buf)
	if room > 0 {
		n := min(room, len(p))
		b.buf = append(b.buf, p[:n]...)
		b.dropped += len(p) - n
	} else {
		b.dropped += len(p)
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	s := string(b.buf)
	if b.dropped > 0 {
		s += fmt.Sprintf("\n…(%d bayt kısaltıldı)", b.dropped)
	}
	return s
}
