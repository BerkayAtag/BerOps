// ber-agentsim, test ve demo için çok sayıda sanal ajanı aynı süreçte simüle eder.
// Her sanal ajan gerçek ajanla aynı istemci ve heartbeat kodunu kullanır; yalnızca
// makine bilgisi sahte üretilir ve kimlik bellekte tutulur.
//
//	go run ./agent/cmd/ber-agentsim -server https://localhost:52311 -key berreg_... -ca-hash sha256:... -n 50
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BerkayAtag/automation-ber/agent/internal/client"
	"github.com/BerkayAtag/automation-ber/agent/internal/identity"
	"github.com/BerkayAtag/automation-ber/agent/internal/inventory"
	"github.com/BerkayAtag/automation-ber/agent/internal/jobs"
	"github.com/BerkayAtag/automation-ber/agent/internal/runner"
	"github.com/BerkayAtag/automation-ber/agent/internal/scanner"
	"github.com/BerkayAtag/automation-ber/agent/internal/simdata"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

var profiles = []simdata.Profile{
	{Platform: "windows", Name: "Windows 11 Pro", Version: "23H2", Build: "10.0.22631.4460", Arch: "amd64"},
	{Platform: "windows", Name: "Windows 11 Enterprise", Version: "24H2", Build: "10.0.26100.2314", Arch: "amd64"},
	{Platform: "windows", Name: "Windows 10 Enterprise", Version: "22H2", Build: "10.0.19045.5131", Arch: "amd64"},
	{Platform: "windows", Name: "Windows Server 2022 Standard", Version: "21H2", Build: "10.0.20348.2849", Arch: "amd64"},
	{Platform: "darwin", Name: "macOS", Version: "15.1", Build: "24B83", Arch: "arm64"},
	{Platform: "darwin", Name: "macOS", Version: "14.7.1", Build: "23H222", Arch: "arm64"},
	{Platform: "darwin", Name: "macOS", Version: "13.7.1", Build: "22H221", Arch: "amd64"},
}

func main() {
	server := flag.String("server", "https://localhost:52311", "ajan API adresi")
	key := flag.String("key", "", "kayıt anahtarı")
	caHash := flag.String("ca-hash", "", "sunucu CA parmak izi")
	n := flag.Int("n", 10, "sanal ajan sayısı")
	prefix := flag.String("prefix", "SIM", "hostname öneki")
	firstScan := flag.Duration("first-scan", 30*time.Second, "kayıttan sonraki ilk envanterin en uzun gecikmesi")
	flag.Parse()
	if *key == "" || *caHash == "" {
		fmt.Fprintln(os.Stderr, "hata: -key ve -ca-hash gerekli")
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Her sanal ajanın envanter durumu geçici bir dizinde tutulur ve çıkışta silinir.
	root, err := os.MkdirTemp("", "ber-agentsim-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(root)

	var enrolled, failed atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= *n; i++ {
		p := profiles[(i-1)%len(profiles)]
		tag := "WIN"
		if p.Platform == "darwin" {
			tag = "MAC"
		}
		host := protocol.HostInfo{
			Hostname:     fmt.Sprintf("%s-%s-%04d", *prefix, tag, i),
			OSPlatform:   p.Platform,
			OSName:       p.Name,
			OSVersion:    p.Version,
			OSBuild:      p.Build,
			Arch:         p.Arch,
			IPAddresses:  []string{fmt.Sprintf("10.%d.%d.%d", 10+i/65536%200, i/256%256, i%256)},
			AgentVersion: "0.1.0-sim",
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Kayıtları zamana yay: sunucuya aynı anda yüzlerce el sıkışma gelmesin.
			time.Sleep(time.Duration(mrand.Int64N(int64(time.Second) * int64(1+*n/50))))
			sim := simAgent{index: i, profile: p, host: host, dir: filepath.Join(root, host.Hostname), firstScan: *firstScan}
			if err := sim.run(ctx, log, *server, *caHash, *key, &enrolled); err != nil && !errors.Is(err, context.Canceled) {
				failed.Add(1)
				log.Error("sanal ajan başarısız", "hostname", host.Hostname, "hata", err)
			}
		}()
	}

	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Info("durum", "kayıtlı", enrolled.Load(), "başarısız", failed.Load(), "toplam", *n)
			}
		}
	}()

	wg.Wait()
}

type simAgent struct {
	index     int
	profile   simdata.Profile
	host      protocol.HostInfo
	dir       string
	firstScan time.Duration
}

func (a simAgent) run(ctx context.Context, log *slog.Logger, server, caHash, regKey string, enrolled *atomic.Int64) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	csr, err := identity.NewCSR(key)
	if err != nil {
		return err
	}
	ec, err := client.New(server, caHash, nil)
	if err != nil {
		return err
	}
	resp, err := ec.Enroll(ctx, protocol.EnrollRequest{RegistrationKey: regKey, CSRPEM: string(csr), Host: a.host})
	if err != nil {
		return err
	}
	enrolled.Add(1)
	blk, _ := pem.Decode([]byte(resp.CertificatePEM))
	if blk == nil {
		return errors.New("sertifika PEM değil")
	}
	cert := &tls.Certificate{Certificate: [][]byte{blk.Bytes}, PrivateKey: key}
	hc, err := client.New(server, caHash, cert)
	if err != nil {
		return err
	}
	alog := log.With("hostname", a.host.Hostname)

	// Gerçek ajanla aynı zamanlayıcı; yalnızca toplama sahte veriyle yapılır.
	sc := scanner.New(a.dir, a.profile.Platform, hc, alog)
	sc.FirstScanMaxDelay = a.firstScan
	sc.Collect = func(_ context.Context, opts inventory.Options) *inventory.Snapshot {
		return simdata.Generate(a.index, a.profile, opts.IncludeMissing)
	}
	if err := sc.Load(); err != nil {
		return err
	}
	go sc.Run(ctx)

	// İşler gerçek ajanla aynı yoldan işlenir (imza doğrulama, hız sınırlı indirme, SHA-256
	// kontrolü); yalnızca komut çalıştırılmaz, başarılı sonuç taklit edilir.
	actionKey := ed25519.PublicKey(resp.ActionKey)
	jr := jobs.New(filepath.Join(a.dir, "jobs"), hc, alog, resp.AgentID, func() ed25519.PublicKey { return actionKey })
	jr.Exec = func(_ context.Context, s jobs.Spec) jobs.Result {
		time.Sleep(time.Duration(500+mrand.IntN(2500)) * time.Millisecond)
		return jobs.Result{Stdout: fmt.Sprintf("[sanal ajan] %s kabuğunda çalıştırıldı:\n%s\n", s.Shell, s.Command)}
	}
	go jr.Run(ctx)

	r := &runner.Runner{
		Client:          hc,
		Log:             alog,
		Collect:         func() protocol.HostInfo { return a.host },
		Interval:        time.Duration(resp.HeartbeatSeconds) * time.Second,
		StartedAt:       time.Now().UTC(),
		InventoryHashes: sc.UploadedHashes,
		OnResponse: func(hr *protocol.HeartbeatResponse) {
			sc.ApplyHeartbeat(hr)
			jr.Notify(hr.PendingJobs)
		},
	}
	r.Run(ctx)
	return ctx.Err()
}
