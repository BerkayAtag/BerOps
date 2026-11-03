package jobs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"unicode/utf16"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

// UpdateSpec, ajan güncellemesinin kurulum bilgisidir.
type UpdateSpec struct {
	// File, indirilip özeti doğrulanmış kurulum paketidir (MSI / PKG).
	File string
	// LogFile, yükleyicinin günlüğüdür; başarısızlıkta son kısmı sonuca eklenir.
	LogFile string
}

// UpdateWait, ajandan bağımsız başlatılan yükleyicinin bitmesini bekler ve çıkış kodunu döner.
// Yükleyici servisi yeniden başlatırsa ajan bu sırada durdurulur ve bağlam iptal edilir.
type UpdateWait func(ctx context.Context) (int, error)

// updateSuccessCodes, yükleyicinin başarılı sayılan çıkış kodlarıdır (MSI 3010/1641:
// yeniden başlatma gerekli).
var updateSuccessCodes = []int{0, 3010, 1641}

// errUpdateUnsupported, ajan güncellemesinin bu ajanda yapılamadığını bildirir.
var errUpdateUnsupported = errors.New("ajan güncellemesi bu platformda desteklenmiyor")

// runUpdate, ajan güncellemesini yürütür: paketi indirir, yükleyiciyi ajandan bağımsız başlatır
// ve günlüğe başlangıç sürümünü yazar. Kurulum servisi yeniden başlattığında sonucu yeni ajan
// (load) bildirir; ajan çalışırken yükleyici biterse güncelleme başarısız sayılır.
func (r *Runner) runUpdate(ctx context.Context, job *protocol.Job) {
	if job.Package.Installer != protocol.AgentUpdateInstaller(runtime.GOOS) {
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed,
			Error: fmt.Sprintf("%s paketi bu platformda ajan güncellemesi için kullanılamaz", job.Package.Installer)})
		return
	}
	if r.StartUpdate == nil {
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: errUpdateUnsupported.Error()})
		return
	}
	file, ok := r.download(ctx, job)
	if !ok {
		return
	}
	logFile := filepath.Join(r.Dir, "updates", job.ID+".log")
	if err := os.MkdirAll(filepath.Dir(logFile), 0o700); err != nil {
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: err.Error()})
		return
	}
	_ = os.Remove(logFile)
	r.mu.Lock()
	r.journal[journalKey(job)] = &journalEntry{JobID: job.ID, Status: protocol.TargetRunning,
		UpdateFrom: r.Version, UpdateLog: logFile, PackageSHA: job.Package.SHA256, At: r.now()}
	r.mu.Unlock()
	r.save()
	_ = r.report(ctx, job.ID, protocol.JobStatusRequest{Status: protocol.TargetRunning})

	r.Log.Info("ajan güncellemesi başlatılıyor", "iş", job.ID, "paket", job.Package.Name+" "+job.Package.Version, "sürüm", r.Version)
	wait, err := r.StartUpdate(ctx, UpdateSpec{File: file, LogFile: logFile})
	if err != nil {
		r.finish(ctx, job, protocol.JobStatusRequest{Status: protocol.TargetFailed, Error: "yükleyici başlatılamadı: " + err.Error()})
		return
	}
	code, err := wait(ctx)
	if ctx.Err() != nil {
		// Ajan durduruluyor (yükleyici servisi yeniden başlatıyor): sonucu yeni ajan bildirir.
		return
	}
	rep := protocol.JobStatusRequest{Status: protocol.TargetFailed, ExitCode: &code, Stderr: updateLogTail(logFile)}
	switch {
	case err != nil:
		rep.Error = "yükleyici beklenemedi: " + err.Error()
	case slices.Contains(updateSuccessCodes, code):
		rep.Error = fmt.Sprintf("kurulum bitti ancak ajan yeniden başlamadı; sürüm değişmedi (%s)", r.Version)
	default:
		rep.Error = fmt.Sprintf("yükleyici %d çıkış koduyla başarısız oldu", code)
	}
	r.finish(context.WithoutCancel(ctx), job, rep)
}

// resolveUpdate, yeniden başlatma sırasında yarım kalan güncellemenin sonucunu belirler: ajan
// sürümü değiştiyse güncelleme başarılıdır.
func (r *Runner) resolveUpdate(e *journalEntry) {
	zero := 0
	if r.Version != e.UpdateFrom {
		e.Status = protocol.TargetSucceeded
		e.Report = &protocol.JobStatusRequest{Status: protocol.TargetSucceeded, ExitCode: &zero,
			Stdout: fmt.Sprintf("Ajan %s sürümünden %s sürümüne güncellendi.", e.UpdateFrom, r.Version)}
		if e.PackageSHA != "" {
			_ = os.RemoveAll(filepath.Join(r.Dir, "cache", e.PackageSHA))
		}
	} else {
		e.Status = protocol.TargetFailed
		e.Report = &protocol.JobStatusRequest{Status: protocol.TargetFailed,
			Error:  fmt.Sprintf("ajan yeniden başladı ancak sürüm değişmedi (%s)", r.Version),
			Stderr: updateLogTail(e.UpdateLog)}
	}
	e.Reported = false
	if r.FinishUpdate != nil {
		r.FinishUpdate(e.UpdateLog)
	}
}

// updateLogTail, yükleyici günlüğünün son kısmını UTF-8 olarak döner (msiexec günlüğü UTF-16
// olabilir).
func updateLogTail(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	b = decodeUTF16(b)
	const max = 16 << 10
	if len(b) > max {
		b = b[len(b)-max:]
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	return string(bytes.ToValidUTF8(b, []byte("�")))
}

// decodeUTF16, BOM'lu veya her ikinci baytı sıfır olan UTF-16LE metni UTF-8'e çevirir.
func decodeUTF16(b []byte) []byte {
	le := len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE
	if !le && !(len(b) >= 4 && b[1] == 0 && b[3] == 0 && b[0] != 0) {
		return b
	}
	if le {
		b = b[2:]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return []byte(string(utf16.Decode(u)))
}
