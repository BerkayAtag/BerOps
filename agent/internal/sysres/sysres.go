// Package sysres, ajanın sistem kaynaklarını az kullanmasını sağlar: süreç önceliğini
// düşürür, alt süreçleri düşük öncelikte ve CPU sınırıyla çalıştırır, ajan içindeki
// taramaları CPU bütçesine göre kısar ve pil/kullanıcı etkinliği durumunu bildirir.
package sysres

import (
	"context"
	"errors"
	"runtime"
	"time"
)

// ErrUnsupported, kontrol bu platformda yapılamıyorsa döner.
var ErrUnsupported = errors.New("bu platformda desteklenmiyor")

// Throttle, ajan içinde sıralı yapılan işin CPU kullanımını sınırlar. Her iş biriminden
// sonra Tick çağrılır; geçen süre ile hedef oran karşılaştırılıp gerektiği kadar beklenir
// (görev döngüsü / duty cycle). Tek goroutine en fazla bir çekirdek kullandığından,
// sistem geneli sınır çekirdek sayısıyla ölçeklenir.
type Throttle struct {
	// coreFraction, tek çekirdek üzerinden izin verilen çalışma oranıdır (0-1].
	coreFraction float64
	minSlice     time.Duration
	workStart    time.Time
	now          func() time.Time
	sleep        func(context.Context, time.Duration) bool
}

// NewThrottle, sistem genelinde en fazla limitPercent CPU kullanacak bir kısıcı üretir.
func NewThrottle(limitPercent int) *Throttle {
	return newThrottle(limitPercent, runtime.NumCPU())
}

func newThrottle(limitPercent, cores int) *Throttle {
	if limitPercent <= 0 {
		limitPercent = 10
	}
	f := float64(limitPercent) * float64(cores) / 100
	if f > 1 {
		f = 1
	}
	t := &Throttle{coreFraction: f, minSlice: 20 * time.Millisecond, now: time.Now, sleep: sleepCtx}
	t.workStart = t.now()
	return t
}

// Tick, son Tick'ten bu yana yapılan işe göre bekler. Bağlam iptal edilirse false döner.
func (t *Throttle) Tick(ctx context.Context) bool {
	if t == nil || t.coreFraction >= 1 {
		return ctx.Err() == nil
	}
	worked := t.now().Sub(t.workStart)
	if worked < t.minSlice {
		return ctx.Err() == nil
	}
	pause := time.Duration(float64(worked) * (1/t.coreFraction - 1))
	ok := t.sleep(ctx, pause)
	t.workStart = t.now()
	return ok
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	tm := time.NewTimer(d)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-tm.C:
		return true
	}
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' || c == '\r' {
			return s[:i]
		}
	}
	if len(s) > 300 {
		return s[:300]
	}
	return s
}
