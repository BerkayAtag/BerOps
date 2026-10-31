package sysres

import (
	"context"
	"testing"
	"time"
)

func TestThrottleDutyCycle(t *testing.T) {
	now := time.Unix(0, 0)
	var slept []time.Duration
	th := newThrottle(10, 4) // sistem geneli %10, 4 çekirdek → tek çekirdekte %40
	th.now = func() time.Time { return now }
	th.workStart = now
	th.sleep = func(_ context.Context, d time.Duration) bool { slept = append(slept, d); now = now.Add(d); return true }

	now = now.Add(5 * time.Millisecond) // eşiğin altında: beklemez
	th.Tick(context.Background())
	now = now.Add(35 * time.Millisecond) // toplam 40 ms çalışma
	th.Tick(context.Background())
	if len(slept) != 1 || slept[0] != 60*time.Millisecond {
		t.Fatalf("40 ms çalışma için %%40 oranında 60 ms beklenmeli: %v", slept)
	}
}

func TestThrottleNoLimitWhenBudgetCoversCore(t *testing.T) {
	th := newThrottle(50, 2) // 2 çekirdekte %50 = tam bir çekirdek
	called := false
	th.sleep = func(context.Context, time.Duration) bool { called = true; return true }
	th.workStart = time.Now().Add(-time.Second)
	if !th.Tick(context.Background()) || called {
		t.Error("bütçe bir çekirdeği karşılıyorsa beklenmemeli")
	}
}

func TestThrottleRespectsCancel(t *testing.T) {
	th := newThrottle(1, 1)
	th.workStart = time.Now().Add(-time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if th.Tick(ctx) {
		t.Error("iptal edilen bağlamda false dönmeli")
	}
	var nilT *Throttle
	if !nilT.Tick(context.Background()) {
		t.Error("nil kısıcı işi engellememeli")
	}
}
