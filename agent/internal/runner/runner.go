// Package runner, ajanın ana döngüsünü (kayıt ve heartbeat) yürütür.
package runner

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/BerkayAtag/automation-ber/agent/internal/client"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

const (
	// MaxBackoff, ardışık hatalarda bekleme süresinin üst sınırıdır.
	MaxBackoff = 15 * time.Minute
	// jitterFraction, heartbeat aralığına eklenen rastgele sapma oranıdır (±%10).
	jitterFraction = 0.10
	// maxStartDelay, açılışta ilk heartbeat'ten önceki en uzun rastgele beklemedir. Toplu
	// yeniden başlatmalardan sonra binlerce ajanın aynı saniyede bağlanmasını önler.
	maxStartDelay = 15 * time.Second
	// maxReportedErrors, bir sonraki başarılı heartbeat'te bildirilecek en fazla hata sayısıdır.
	maxReportedErrors = 5
)

// Jitter, d süresine ±frac oranında rastgele sapma ekler.
func Jitter(d time.Duration, frac float64, rnd func() float64) time.Duration {
	delta := (rnd()*2 - 1) * frac * float64(d)
	return d + time.Duration(delta)
}

// Backoff, n. ardışık hata için beklenecek süredir: base·2^(n-1), en fazla max.
func Backoff(n int, base, max time.Duration) time.Duration {
	if n < 1 {
		return base
	}
	d := base
	for i := 1; i < n; i++ {
		d *= 2
		if d >= max {
			return max
		}
	}
	return min(d, max)
}

// Heartbeater, Heartbeat isteği gönderebilen istemcidir (testlerde sahte sürüm kullanılır).
type Heartbeater interface {
	Heartbeat(ctx context.Context, req protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error)
}

// Runner, heartbeat döngüsüdür.
type Runner struct {
	Client    Heartbeater
	Log       *slog.Logger
	Collect   func() protocol.HostInfo
	Interval  time.Duration
	StartedAt time.Time
	// OnResponse, her başarılı heartbeat'ten sonra çağrılır (isteğe bağlı).
	OnResponse func(*protocol.HeartbeatResponse)

	rnd   func() float64
	sleep func(ctx context.Context, d time.Duration) bool
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Run, bağlam iptal edilene kadar heartbeat gönderir.
func (r *Runner) Run(ctx context.Context) {
	if r.rnd == nil {
		r.rnd = rand.Float64
	}
	if r.sleep == nil {
		r.sleep = sleepCtx
	}
	if r.Interval <= 0 {
		r.Interval = 60 * time.Second
	}
	if !r.sleep(ctx, time.Duration(r.rnd()*float64(min(r.Interval, maxStartDelay)))) {
		return
	}

	failures := 0
	var pending []string
	for {
		req := protocol.HeartbeatRequest{Host: r.Collect(), AgentStartedAt: r.StartedAt, Errors: pending}
		resp, err := r.Client.Heartbeat(ctx, req)
		if ctx.Err() != nil {
			return
		}
		var wait time.Duration
		if err != nil {
			failures++
			wait = Jitter(Backoff(failures, r.Interval, MaxBackoff), 0.2, r.rnd)
			r.Log.Warn("heartbeat başarısız", "hata", err, "ardışık", failures, "sonraki_deneme", wait.Round(time.Second))
			pending = appendError(pending, time.Now().UTC().Format(time.RFC3339)+" heartbeat: "+err.Error())
			var apiErr *client.APIError
			if errors.As(err, &apiErr) && apiErr.Status == http.StatusForbidden {
				r.Log.Error("sunucu bu ajanı reddetti veya iptal etti; yönetici onayı olmadan iş alınamaz")
			}
		} else {
			if failures > 0 {
				r.Log.Info("sunucu bağlantısı yeniden kuruldu", "ardışık_hata", failures)
			}
			failures = 0
			pending = nil
			if resp.HeartbeatSeconds > 0 {
				r.Interval = time.Duration(resp.HeartbeatSeconds) * time.Second
			}
			if r.OnResponse != nil {
				r.OnResponse(resp)
			}
			wait = Jitter(r.Interval, jitterFraction, r.rnd)
			r.Log.Debug("heartbeat gönderildi", "durum", resp.Status, "sonraki", wait.Round(time.Second))
		}
		if !r.sleep(ctx, wait) {
			return
		}
	}
}

func appendError(list []string, e string) []string {
	list = append(list, e)
	if len(list) > maxReportedErrors {
		list = list[len(list)-maxReportedErrors:]
	}
	return list
}
