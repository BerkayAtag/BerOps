package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

type fakeClient struct {
	mu      sync.Mutex
	queue   []protocol.SignedJob
	results map[string]protocol.RemoteResult
	done    chan struct{}
}

func (f *fakeClient) RemotePoll(ctx context.Context) (*protocol.SignedJob, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.queue) == 0 {
		time.Sleep(20 * time.Millisecond)
		return nil, nil
	}
	j := f.queue[0]
	f.queue = f.queue[1:]
	return &j, nil
}

func (f *fakeClient) RemoteResult(_ context.Context, id string, r protocol.RemoteResult) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results[id] = r
	if len(f.results) == 3 {
		close(f.done)
	}
	return nil
}

func TestSessionVerifiesAndHonorsFlags(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	c := &fakeClient{results: map[string]protocol.RemoteResult{}, done: make(chan struct{})}
	s := New(c, slog.New(slog.NewTextHandler(io.Discard, nil)), "m1", func() ed25519.PublicKey { return pub })
	s.Handle = func(_ context.Context, op string, _ json.RawMessage) (any, error) {
		return map[string]string{"op": op}, nil
	}
	exp := time.Now().Add(time.Minute)
	add := func(key ed25519.PrivateKey, r protocol.RemoteRequest) {
		r.ExpiresAt = exp
		sj, _ := protocol.SignRemote(key, r)
		c.queue = append(c.queue, sj)
	}
	add(priv, protocol.RemoteRequest{ID: "perf", MachineID: "m1", Op: protocol.RemotePerformance})
	add(priv, protocol.RemoteRequest{ID: "kayit", MachineID: "m1", Op: protocol.RemoteRegistrySet})
	add(other, protocol.RemoteRequest{ID: "sahte", MachineID: "m1", Op: protocol.RemotePerformance})
	add(priv, protocol.RemoteRequest{ID: "baskasi", MachineID: "m2", Op: protocol.RemotePerformance})
	add(priv, protocol.RemoteRequest{ID: "servis", MachineID: "m1", Op: protocol.RemoteServicesList})

	now := time.Now()
	until := now.Add(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Apply(ctx, &protocol.HeartbeatResponse{ServerTime: now, RemoteUntil: &until,
		Remote: &protocol.RemoteFlags{Performance: true, Services: true, RegistryRead: true}})
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("sonuçlar gelmedi: %v", c.results)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.results["perf"]; !r.OK || string(r.Data) != `{"op":"performance"}` {
		t.Errorf("performans = %+v", r)
	}
	if r := c.results["kayit"]; r.OK || r.Error == "" {
		t.Errorf("kayıt defteri yazma kapalıyken reddedilmeli: %+v", r)
	}
	if _, ok := c.results["sahte"]; ok {
		t.Error("başka anahtarla imzalı isteğe yanıt verilmemeli")
	}
	if _, ok := c.results["baskasi"]; ok {
		t.Error("başka makineye ait isteğe yanıt verilmemeli")
	}
	if !c.results["servis"].OK {
		t.Error("servis listesi izinli")
	}
}

func TestSessionNotStartedWithoutFlags(t *testing.T) {
	c := &fakeClient{results: map[string]protocol.RemoteResult{}, done: make(chan struct{})}
	s := New(c, slog.New(slog.NewTextHandler(io.Discard, nil)), "m1", func() ed25519.PublicKey { return nil })
	until := time.Now().Add(time.Minute)
	s.Apply(context.Background(), &protocol.HeartbeatResponse{RemoteUntil: &until, Remote: &protocol.RemoteFlags{}})
	if s.running {
		t.Error("hiçbir özellik açık değilken oturum başlamamalı")
	}
}

func TestPerformanceSnapshot(t *testing.T) {
	snap, err := Performance(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snap.CPUCores < 1 || snap.MemTotal == 0 || snap.MemUsed == 0 || len(snap.Disks) == 0 || len(snap.Processes) == 0 {
		t.Errorf("eksik performans bilgisi: cores=%d mem=%d/%d disks=%d procs=%d",
			snap.CPUCores, snap.MemUsed, snap.MemTotal, len(snap.Disks), len(snap.Processes))
	}
	if snap.CPUPercent < 0 || snap.CPUPercent > 100 {
		t.Errorf("CPU yüzdesi = %v", snap.CPUPercent)
	}
}

func TestListServices(t *testing.T) {
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		t.Skip("yalnızca Windows ve macOS")
	}
	list, err := ListServices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	running := 0
	for _, s := range list {
		if s.State == "running" {
			running++
		}
	}
	if len(list) < 5 || running == 0 {
		t.Errorf("servis listesi = %d, çalışan %d", len(list), running)
	}
}
