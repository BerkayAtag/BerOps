package runner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func TestJitterStaysWithinBounds(t *testing.T) {
	base := 60 * time.Second
	for _, r := range []float64{0, 0.25, 0.5, 0.75, 0.999} {
		got := Jitter(base, 0.1, func() float64 { return r })
		if got < 54*time.Second || got > 66*time.Second {
			t.Errorf("rnd=%v için %v ±%%10 dışında", r, got)
		}
	}
	if Jitter(base, 0.1, func() float64 { return 0.5 }) != base {
		t.Error("rnd=0.5 sapma üretmemeli")
	}
}

func TestBackoff(t *testing.T) {
	base := time.Minute
	cases := map[int]time.Duration{0: base, 1: base, 2: 2 * base, 3: 4 * base, 4: 8 * base, 5: 15 * time.Minute, 50: 15 * time.Minute}
	for n, want := range cases {
		if got := Backoff(n, base, 15*time.Minute); got != want {
			t.Errorf("Backoff(%d) = %v, beklenen %v", n, got, want)
		}
	}
}

type fakeClient struct {
	results []error
	reqs    []protocol.HeartbeatRequest
}

func (f *fakeClient) Heartbeat(_ context.Context, req protocol.HeartbeatRequest) (*protocol.HeartbeatResponse, error) {
	f.reqs = append(f.reqs, req)
	i := len(f.reqs) - 1
	if i < len(f.results) && f.results[i] != nil {
		return nil, f.results[i]
	}
	return &protocol.HeartbeatResponse{Status: "active", HeartbeatSeconds: 30}, nil
}

func TestRunnerBacksOffAndReportsErrors(t *testing.T) {
	fc := &fakeClient{results: []error{errors.New("bağlantı reddedildi"), errors.New("zaman aşımı"), nil, nil}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var waits []time.Duration
	r := &Runner{
		Client:   fc,
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Collect:  func() protocol.HostInfo { return protocol.HostInfo{Hostname: "PC"} },
		Interval: 60 * time.Second,
		rnd:      func() float64 { return 0.5 }, // sapmasız
		sleep: func(_ context.Context, d time.Duration) bool {
			waits = append(waits, d)
			if len(fc.reqs) >= 4 {
				cancel()
				return false
			}
			return true
		},
	}
	r.Run(ctx)

	// waits[0] açılış gecikmesidir.
	want := []time.Duration{15 * time.Second / 2, 60 * time.Second, 120 * time.Second, 30 * time.Second, 30 * time.Second}
	if len(waits) != len(want) {
		t.Fatalf("bekleme sayısı %d, beklenen %d: %v", len(waits), len(want), waits)
	}
	for i := range want {
		if waits[i] != want[i] {
			t.Errorf("bekleme[%d] = %v, beklenen %v", i, waits[i], want[i])
		}
	}
	if got := len(fc.reqs[2].Errors); got != 2 {
		t.Errorf("başarılı heartbeat önceki 2 hatayı bildirmeli, %d bildirdi", got)
	}
	if len(fc.reqs[3].Errors) != 0 {
		t.Error("hatalar bildirildikten sonra temizlenmeli")
	}
	if r.Interval != 30*time.Second {
		t.Errorf("sunucunun bildirdiği aralık uygulanmalı: %v", r.Interval)
	}
}
