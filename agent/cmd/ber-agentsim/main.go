// ber-agentsim, test ve demo için çok sayıda sanal ajanı aynı süreçte simüle eder.
// Her sanal ajan gerçek ajanla aynı istemci ve heartbeat kodunu kullanır; yalnızca
// makine bilgisi sahte üretilir ve kimlik bellekte tutulur.
//
//	go run ./agent/cmd/ber-agentsim -server https://localhost:52311 -key berreg_... -ca-hash sha256:... -n 50
package main

import (
	"context"
	"crypto/ecdsa"
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
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/BerkayAtag/automation-ber/agent/internal/client"
	"github.com/BerkayAtag/automation-ber/agent/internal/identity"
	"github.com/BerkayAtag/automation-ber/agent/internal/runner"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

type profile struct {
	platform, name, version, build, arch string
}

var profiles = []profile{
	{"windows", "Windows 11 Pro", "23H2", "10.0.22631.4460", "amd64"},
	{"windows", "Windows 11 Enterprise", "24H2", "10.0.26100.2314", "amd64"},
	{"windows", "Windows 10 Enterprise", "22H2", "10.0.19045.5131", "amd64"},
	{"windows", "Windows Server 2022 Standard", "21H2", "10.0.20348.2849", "amd64"},
	{"darwin", "macOS", "15.1", "24B83", "arm64"},
	{"darwin", "macOS", "14.7.1", "23H222", "arm64"},
	{"darwin", "macOS", "13.7.1", "22H221", "amd64"},
}

func main() {
	server := flag.String("server", "https://localhost:52311", "ajan API adresi")
	key := flag.String("key", "", "kayıt anahtarı")
	caHash := flag.String("ca-hash", "", "sunucu CA parmak izi")
	n := flag.Int("n", 10, "sanal ajan sayısı")
	prefix := flag.String("prefix", "SIM", "hostname öneki")
	flag.Parse()
	if *key == "" || *caHash == "" {
		fmt.Fprintln(os.Stderr, "hata: -key ve -ca-hash gerekli")
		os.Exit(2)
	}

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var enrolled, failed atomic.Int64
	var wg sync.WaitGroup
	for i := 1; i <= *n; i++ {
		p := profiles[(i-1)%len(profiles)]
		tag := "WIN"
		if p.platform == "darwin" {
			tag = "MAC"
		}
		host := protocol.HostInfo{
			Hostname:     fmt.Sprintf("%s-%s-%04d", *prefix, tag, i),
			OSPlatform:   p.platform,
			OSName:       p.name,
			OSVersion:    p.version,
			OSBuild:      p.build,
			Arch:         p.arch,
			IPAddresses:  []string{fmt.Sprintf("10.%d.%d.%d", 10+i/65536%200, i/256%256, i%256)},
			AgentVersion: "0.1.0-sim",
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Kayıtları zamana yay: sunucuya aynı anda yüzlerce el sıkışma gelmesin.
			time.Sleep(time.Duration(mrand.Int64N(int64(time.Second) * int64(1+*n/50))))
			if err := simulate(ctx, log, *server, *caHash, *key, host, &enrolled); err != nil && !errors.Is(err, context.Canceled) {
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

func simulate(ctx context.Context, log *slog.Logger, server, caHash, regKey string, host protocol.HostInfo, enrolled *atomic.Int64) error {
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
	resp, err := ec.Enroll(ctx, protocol.EnrollRequest{RegistrationKey: regKey, CSRPEM: string(csr), Host: host})
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
	r := &runner.Runner{
		Client:    hc,
		Log:       log.With("hostname", host.Hostname),
		Collect:   func() protocol.HostInfo { return host },
		Interval:  time.Duration(resp.HeartbeatSeconds) * time.Second,
		StartedAt: time.Now().UTC(),
	}
	r.Run(ctx)
	return ctx.Err()
}
