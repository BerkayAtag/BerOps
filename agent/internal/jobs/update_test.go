//go:build !windows

package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// addUpdate, platforma uygun ajan güncelleme işini ekler.
func (e *env) addUpdate(id, installer string) {
	body := []byte("sahte kurulum paketi")
	sum := sha256.Sum256(body)
	e.client.files["pkg-ajan"] = body
	e.add(protocol.Job{ID: id, Kind: protocol.JobUpdateAgent, TimeoutSeconds: 600, Package: &protocol.JobPackage{
		ID: "pkg-ajan", Name: "BerOps Agent", Version: "9.9.9", FileName: "BerOps-Agent." + installer,
		Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Installer: installer,
	}}, e.priv)
}

func updateInstaller(t *testing.T) string {
	inst := protocol.AgentUpdateInstaller(runtime.GOOS)
	if inst == "" {
		t.Skip("bu platformda ajan güncellemesi yok")
	}
	return inst
}

func TestUpdateSucceedsAfterRestart(t *testing.T) {
	inst := updateInstaller(t)
	e := newEnv(t)
	e.r.Version = "1.0.0"
	started := make(chan UpdateSpec, 1)
	e.r.StartUpdate = func(_ context.Context, u UpdateSpec) (UpdateWait, error) {
		if b, err := os.ReadFile(u.File); err != nil || string(b) != "sahte kurulum paketi" {
			t.Errorf("yükleyiciye doğrulanmış paket verilmeli: %q %v", b, err)
		}
		started <- u
		// Gerçekte yükleyici servisi durdurur: bekleme ajan kapanana kadar sürer.
		return func(ctx context.Context) (int, error) { <-ctx.Done(); return -1, ctx.Err() }, nil
	}
	e.addUpdate("guncelle", inst)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.r.Process(ctx); close(done) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("yükleyici başlatılmadı")
	}
	cancel()
	<-done
	if r := e.client.final("guncelle"); r.Status != protocol.TargetRunning {
		t.Fatalf("ajan kapanırken iş running kalmalı: %+v", r)
	}

	// Yeni sürüm ajan aynı veri diziniyle açılır ve sonucu bildirir.
	finished := false
	r2 := New(e.r.Dir, e.client, slog.New(slog.NewTextHandler(io.Discard, nil)), "m1", e.r.Key)
	r2.Version, r2.FinishUpdate = "1.1.0", func(string) { finished = true }
	e.client.jobs = nil
	r2.Process(context.Background())
	r := e.client.final("guncelle")
	if r.Status != protocol.TargetSucceeded || !strings.Contains(r.Stdout, "1.0.0 sürümünden 1.1.0") {
		t.Fatalf("güncelleme başarılı bildirilmeli: %+v", r)
	}
	if !finished {
		t.Error("geçici güncelleme kaynakları temizlenmeli")
	}
}

func TestUpdateFailsWhenVersionUnchanged(t *testing.T) {
	inst := updateInstaller(t)
	e := newEnv(t)
	e.r.Version = "1.0.0"
	e.r.StartUpdate = func(_ context.Context, u UpdateSpec) (UpdateWait, error) {
		_ = os.WriteFile(u.LogFile, []byte("satır 1\nhata: disk dolu\n"), 0o600)
		return func(ctx context.Context) (int, error) { <-ctx.Done(); return -1, ctx.Err() }, nil
	}
	e.addUpdate("ayni", inst)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(300 * time.Millisecond); cancel() }()
	e.r.Process(ctx)

	r2 := New(e.r.Dir, e.client, slog.New(slog.NewTextHandler(io.Discard, nil)), "m1", e.r.Key)
	r2.Version = "1.0.0"
	e.client.jobs = nil
	r2.Process(context.Background())
	r := e.client.final("ayni")
	if r.Status != protocol.TargetFailed || !strings.Contains(r.Error, "sürüm değişmedi") || !strings.Contains(r.Stderr, "disk dolu") {
		t.Fatalf("sürüm değişmeden yeniden başlama başarısız sayılmalı: %+v", r)
	}
}

func TestUpdateInstallerFailsWhileRunning(t *testing.T) {
	inst := updateInstaller(t)
	e := newEnv(t)
	e.r.Version = "1.0.0"
	e.r.StartUpdate = func(_ context.Context, u UpdateSpec) (UpdateWait, error) {
		_ = os.WriteFile(u.LogFile, []byte("Product: BerOps Agent -- Installation failed.\n"), 0o600)
		return func(context.Context) (int, error) { return 1603, nil }, nil
	}
	e.addUpdate("hata", inst)
	e.r.Process(context.Background())
	r := e.client.final("hata")
	if r.Status != protocol.TargetFailed || r.ExitCode == nil || *r.ExitCode != 1603 || !strings.Contains(r.Stderr, "Installation failed") {
		t.Fatalf("yükleyici hatası bildirilmeli: %+v", r)
	}
}

func TestUpdateRejectsWrongInstaller(t *testing.T) {
	inst := updateInstaller(t)
	other := protocol.InstallerMSI
	if inst == protocol.InstallerMSI {
		other = protocol.InstallerPKG
	}
	e := newEnv(t)
	called := false
	e.r.StartUpdate = func(context.Context, UpdateSpec) (UpdateWait, error) { called = true; return nil, nil }
	e.addUpdate("yanlis", other)
	e.r.Process(context.Background())
	if r := e.client.final("yanlis"); r.Status != protocol.TargetFailed || called {
		t.Fatalf("başka platformun paketi kurulmamalı: %+v (çağrıldı: %v)", r, called)
	}
}

func TestDecodeUTF16(t *testing.T) {
	in := []byte{0xFF, 0xFE, 'O', 0, 'k', 0, 0x5F, 0x01} // "Okş" (ş = U+015F)
	if got := string(decodeUTF16(in)); got != "Okş" {
		t.Errorf("UTF-16LE çözülemedi: %q", got)
	}
	if got := string(decodeUTF16([]byte("düz metin"))); got != "düz metin" {
		t.Errorf("UTF-8 metin değişmemeli: %q", got)
	}
}
