//go:build !windows

package jobs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

type fakeClient struct {
	mu       sync.Mutex
	jobs     []protocol.SignedJob
	reports  map[string][]protocol.JobStatusRequest
	files    map[string][]byte
	failNext bool
}

func (f *fakeClient) Jobs(context.Context) ([]protocol.SignedJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs, nil
}

func (f *fakeClient) JobStatus(_ context.Context, id string, r protocol.JobStatusRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reports == nil {
		f.reports = map[string][]protocol.JobStatusRequest{}
	}
	f.reports[id] = append(f.reports[id], r)
	return nil
}

func (f *fakeClient) DownloadPackage(_ context.Context, pkgID, _, dest string) error {
	return os.WriteFile(dest, f.files[pkgID], 0o600)
}

func (f *fakeClient) final(id string) protocol.JobStatusRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.reports[id]
	if len(r) == 0 {
		return protocol.JobStatusRequest{}
	}
	return r[len(r)-1]
}

type env struct {
	t      *testing.T
	pub    ed25519.PublicKey
	priv   ed25519.PrivateKey
	client *fakeClient
	r      *Runner
	runs   int
}

func newEnv(t *testing.T) *env {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{t: t, pub: pub, priv: priv, client: &fakeClient{files: map[string][]byte{}}}
	e.r = New(t.TempDir(), e.client, slog.New(slog.NewTextHandler(io.Discard, nil)), "m1", func() ed25519.PublicKey { return e.pub })
	exec := e.r.Exec
	e.r.Exec = func(ctx context.Context, s Spec) Result { e.runs++; return exec(ctx, s) }
	return e
}

func (e *env) add(j protocol.Job, key ed25519.PrivateKey) {
	if j.MachineID == "" {
		j.MachineID = "m1"
	}
	if j.ExpiresAt.IsZero() {
		j.ExpiresAt = time.Now().Add(time.Hour)
	}
	if j.TimeoutSeconds == 0 {
		j.TimeoutSeconds = 30
	}
	sj, err := protocol.SignJob(key, j)
	if err != nil {
		e.t.Fatal(err)
	}
	e.client.jobs = append(e.client.jobs, sj)
}

func TestCommandSuccessAndExitCodes(t *testing.T) {
	e := newEnv(t)
	e.add(protocol.Job{ID: "ok", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "echo merhaba dünya; echo uyarı >&2"}, e.priv)
	e.add(protocol.Job{ID: "kod3", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "exit 3"}, e.priv)
	e.add(protocol.Job{ID: "kod3izinli", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "exit 3", SuccessCodes: []int{0, 3}}, e.priv)
	e.r.Process(context.Background())

	ok := e.client.final("ok")
	if ok.Status != protocol.TargetSucceeded || ok.ExitCode == nil || *ok.ExitCode != 0 ||
		!strings.Contains(ok.Stdout, "merhaba dünya") || !strings.Contains(ok.Stderr, "uyarı") {
		t.Errorf("başarılı komut = %+v", ok)
	}
	if r := e.client.final("kod3"); r.Status != protocol.TargetFailed || *r.ExitCode != 3 {
		t.Errorf("çıkış kodu 3 başarısız olmalı: %+v", r)
	}
	if r := e.client.final("kod3izinli"); r.Status != protocol.TargetSucceeded {
		t.Errorf("izinli kod başarılı sayılmalı: %+v", r)
	}
	if got := e.client.reports["ok"][0].Status; got != protocol.TargetRunning {
		t.Errorf("ilk bildirim running olmalı: %s", got)
	}
}

func TestRejectsUnsignedAndReplay(t *testing.T) {
	e := newEnv(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	marker := filepath.Join(t.TempDir(), "calisti")
	e.add(protocol.Job{ID: "sahte", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "touch " + marker}, other)
	e.add(protocol.Job{ID: "baskasi", MachineID: "m2", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "touch " + marker}, e.priv)
	e.r.Process(context.Background())
	if _, err := os.Stat(marker); err == nil || e.runs != 0 {
		t.Fatal("başka anahtarla veya başka makine için imzalanmış iş çalıştırılmamalı")
	}
	if len(e.client.reports) != 0 {
		t.Error("güvenilmeyen iş için durum bildirilmemeli")
	}

	e.client.jobs = nil
	e.add(protocol.Job{ID: "tek", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "echo bir"}, e.priv)
	e.r.Process(context.Background())
	e.r.Process(context.Background()) // sunucu aynı işi tekrar gönderirse
	if e.runs != 1 {
		t.Errorf("iş bir kez çalışmalı, %d kez çalıştı", e.runs)
	}
	if n := len(e.client.reports["tek"]); n != 3 {
		t.Errorf("tekrar gelen işin sonucu yeniden bildirilmeli (running + 2 sonuç), %d bildirim", n)
	}

	// Günlük diske yazılır: yeni bir Runner da işi tekrar çalıştırmaz.
	r2 := New(e.r.Dir, e.client, e.r.Log, "m1", e.r.Key)
	r2.Exec = func(context.Context, Spec) Result { e.runs++; return Result{} }
	r2.Process(context.Background())
	if e.runs != 1 {
		t.Error("yeniden başlatılan ajan tamamlanmış işi tekrar çalıştırmamalı")
	}
}

func TestPackageDownloadVerify(t *testing.T) {
	e := newEnv(t)
	body := []byte("#!/bin/sh\necho paket kuruldu\n")
	sum := sha256.Sum256(body)
	e.client.files["p1"] = body
	pkg := &protocol.JobPackage{ID: "p1", FileName: "kur.sh", Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Installer: protocol.InstallerFile}
	var finished []string
	e.r.OnFinished = func(j *protocol.Job) { finished = append(finished, j.ID) }
	e.add(protocol.Job{ID: "dag", Kind: protocol.JobDeployPackage, Shell: protocol.ShellSh, Command: `sh "{file}"`, Package: pkg, RescanAfter: true}, e.priv)

	bad := *pkg
	bad.ID, bad.SHA256 = "p2", strings.Repeat("0", 64)
	e.client.files["p2"] = body
	e.add(protocol.Job{ID: "bozuk", Kind: protocol.JobDeployPackage, Shell: protocol.ShellSh, Command: `sh "{file}"`, Package: &bad}, e.priv)
	e.r.Process(context.Background())

	if r := e.client.final("dag"); r.Status != protocol.TargetSucceeded || !strings.Contains(r.Stdout, "paket kuruldu") {
		t.Errorf("paket işi = %+v", r)
	}
	if e.client.reports["dag"][0].Status != protocol.TargetDownloading {
		t.Error("ilk bildirim downloading olmalı")
	}
	if len(finished) != 1 || finished[0] != "dag" {
		t.Errorf("başarılı dağıtımdan sonra yeniden tarama istenmeli: %v", finished)
	}
	if r := e.client.final("bozuk"); r.Status != protocol.TargetFailed || !strings.Contains(r.Error, "özeti") {
		t.Errorf("özeti uyuşmayan paket çalıştırılmamalı: %+v", r)
	}
	if e.runs != 1 {
		t.Errorf("yalnızca doğrulanan paket çalışmalı, %d", e.runs)
	}
}

func TestTimeoutKillsProcessGroup(t *testing.T) {
	e := newEnv(t)
	pidFile := filepath.Join(t.TempDir(), "alt.pid")
	// Komutun arka planda başlattığı uzun süreç de zaman aşımında sonlandırılmalı.
	e.add(protocol.Job{ID: "uzun", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, TimeoutSeconds: 1,
		Command: "sleep 300 & echo $! > " + pidFile + "; sleep 60"}, e.priv)
	start := time.Now()
	e.r.Process(context.Background())
	if d := time.Since(start); d > 20*time.Second {
		t.Fatalf("zaman aşımı uygulanmadı (%s)", d)
	}
	if r := e.client.final("uzun"); r.Status != protocol.TargetFailed || !strings.Contains(r.Error, "zaman aşımı") {
		t.Errorf("zaman aşımı sonucu = %+v", r)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	deadline := time.Now().Add(3 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("arka plandaki alt süreç (%d) zaman aşımından sonra yaşıyor", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestInterruptedJobReportedAsFailed(t *testing.T) {
	e := newEnv(t)
	e.r.load()
	e.r.setJournal(&protocol.Job{ID: "yarim"}, protocol.TargetRunning, nil, false)
	r2 := New(e.r.Dir, e.client, e.r.Log, "m1", e.r.Key)
	r2.Process(context.Background())
	if r := e.client.final("yarim"); r.Status != protocol.TargetFailed || !strings.Contains(r.Error, "yeniden başladı") {
		t.Errorf("yarıda kalan iş başarısız bildirilmeli: %+v", r)
	}
}

func TestClip(t *testing.T) {
	s := strings.Repeat("ş", protocol.MaxOutputBytes)
	out := clip(s)
	if len(out) > protocol.MaxOutputBytes+64 || !strings.Contains(out, "kısaltıldı") || !strings.HasPrefix(out, "şş") {
		t.Errorf("kısaltma hatalı: %d bayt", len(out))
	}
	if clip("a\xffb") != "a�b" {
		t.Error("geçersiz UTF-8 düzeltilmeli")
	}
}

func TestRelativeDataDir(t *testing.T) {
	e := newEnv(t)
	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	parent := t.TempDir()
	if err := os.Chdir(parent); err != nil {
		t.Fatal(err)
	}
	r := New("ajan-verisi", e.client, e.r.Log, "m1", e.r.Key)
	e.add(protocol.Job{ID: "goreli", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "echo tamam"}, e.priv)
	r.Process(context.Background())
	if res := e.client.final("goreli"); res.Status != protocol.TargetSucceeded || !strings.Contains(res.Stdout, "tamam") {
		t.Errorf("göreli veri dizininde komut çalışmalı: %+v", res)
	}
}

func TestTailFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	var b strings.Builder
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&b, "satır %03d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := tailFile(path, 50)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "satır") || !strings.HasSuffix(out, "satır 099\n") || len(out) > 50 {
		t.Errorf("son kısım = %q", out)
	}
	all, _ := tailFile(path, 1<<20)
	if all != b.String() {
		t.Error("küçük dosya tamamen dönmeli")
	}
	if _, err := tailFile(filepath.Join(t.TempDir(), "yok.log"), 10); err == nil {
		t.Error("olmayan dosya hata vermeli")
	}
}

func TestRetryAttemptRunsAgain(t *testing.T) {
	e := newEnv(t)
	e.add(protocol.Job{ID: "tekrar", Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "exit 1"}, e.priv)
	e.r.Process(context.Background())
	if r := e.client.final("tekrar"); r.Status != protocol.TargetFailed || e.runs != 1 {
		t.Fatalf("ilk deneme başarısız olmalı: %+v (%d)", r, e.runs)
	}
	// Sunucu aynı aksiyonu 1. yeniden deneme olarak yeniden imzalar: iş yeniden çalışır.
	e.client.jobs = nil
	e.add(protocol.Job{ID: "tekrar", Attempt: 1, Kind: protocol.JobRunCommand, Shell: protocol.ShellSh, Command: "exit 0"}, e.priv)
	e.r.Process(context.Background())
	e.r.Process(context.Background())
	if e.runs != 2 {
		t.Fatalf("yeniden deneme bir kez çalışmalı, toplam %d çalıştırma", e.runs)
	}
	if r := e.client.final("tekrar"); r.Status != protocol.TargetSucceeded {
		t.Errorf("yeniden deneme sonucu aynı aksiyona bildirilmeli: %+v", r)
	}
}
