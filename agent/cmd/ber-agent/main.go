// ber-agent, Automation BER istemci ajanıdır (Windows servisi / macOS launchd daemon'ı).
//
//	ber-agent configure -server https://ber.example.test:52311 -key berreg_... -ca-hash sha256:...
//	ber-agent enroll    -server https://ber.example.test:52311 -key berreg_... -ca-hash sha256:...
//	ber-agent run
//	ber-agent status
//	ber-agent version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/BerkayAtag/automation-ber/agent/internal/client"
	"github.com/BerkayAtag/automation-ber/agent/internal/config"
	"github.com/BerkayAtag/automation-ber/agent/internal/hostinfo"
	"github.com/BerkayAtag/automation-ber/agent/internal/identity"
	"github.com/BerkayAtag/automation-ber/agent/internal/paths"
	"github.com/BerkayAtag/automation-ber/agent/internal/runner"
	"github.com/BerkayAtag/automation-ber/agent/internal/service"
	"github.com/BerkayAtag/automation-ber/shared/protocol"
	"github.com/BerkayAtag/automation-ber/shared/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Kullanım: ber-agent <komut> [seçenekler]

Komutlar:
  run        Ajanı çalıştırır (servis olarak ya da ön planda)
  configure  Sunucu adresini, kayıt anahtarını ve CA parmak izini kaydeder (kayıt servis başlayınca yapılır)
  enroll     Yapılandırmayı kaydeder ve hemen kaydolur
  status     Kayıt durumunu gösterir
  version    Sürümü yazdırır
`)
}

func run(args []string) error {
	// Servis yöneticisi ajanı argümansız başlatır.
	if len(args) == 0 {
		if service.IsService() {
			args = []string{"run"}
		} else {
			usage()
			return errors.New("komut gerekli")
		}
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(args)
	case "configure":
		return cmdConfigure(args, false)
	case "enroll":
		return cmdConfigure(args, true)
	case "status":
		return cmdStatus(args)
	case "version":
		fmt.Printf("ber-agent %s (%s)\n", version.Version, version.Commit)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("bilinmeyen komut: %s", cmd)
	}
}

func dataDirFlag(fs *flag.FlagSet) *string {
	return fs.String("data-dir", paths.DefaultDataDir(), "veri dizini")
}

// newLogger, döngüsel log dosyasına (10 MB × 5) ve ön planda çalışırken stderr'e yazar.
func newLogger(dataDir, level string, foreground bool) (*slog.Logger, io.Closer, error) {
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, nil, err
	}
	lj := &lumberjack.Logger{
		Filename:   filepath.Join(logDir, "agent.log"),
		MaxSize:    10, // MB
		MaxBackups: 5,
		MaxAge:     30, // gün
		Compress:   true,
	}
	var w io.Writer = lj
	if foreground {
		w = io.MultiWriter(lj, os.Stderr)
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl})), lj, nil
}

func cmdConfigure(args []string, enrollNow bool) error {
	fs := flag.NewFlagSet("configure", flag.ExitOnError)
	dataDir := dataDirFlag(fs)
	server := fs.String("server", "", "sunucu (veya relay) adresi, ör. https://ber.example.test:52311")
	key := fs.String("key", "", "kayıt anahtarı (berreg_...)")
	caHash := fs.String("ca-hash", "", "sunucu CA parmak izi (sha256:...)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg := config.Config{
		ServerURL:       strings.TrimRight(strings.TrimSpace(*server), "/"),
		CAHash:          strings.TrimSpace(*caHash),
		RegistrationKey: strings.TrimSpace(*key),
	}
	if cfg.RegistrationKey == "" {
		return errors.New("-key gerekli")
	}
	if err := config.Save(*dataDir, cfg); err != nil {
		return err
	}
	fmt.Println("Yapılandırma kaydedildi:", filepath.Join(*dataDir, config.FileName))
	if !enrollNow {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := enroll(ctx, *dataDir, cfg, hostinfo.New())
	if err != nil {
		return err
	}
	fmt.Printf("Kayıt başarılı. Ajan ID: %s, durum: %s\n", st.AgentID, st.Status)
	if st.Status == protocol.StatusPending {
		fmt.Println("Makine konsolda yönetici onayı bekliyor.")
	}
	return nil
}

// enroll, kayıt işlemini yapar ve başarılı olursa kayıt anahtarını yapılandırmadan siler.
func enroll(ctx context.Context, dataDir string, cfg config.Config, hi *hostinfo.Collector) (*identity.State, error) {
	if cfg.RegistrationKey == "" {
		return nil, errors.New("kayıt anahtarı yapılandırılmamış")
	}
	ids := identity.Store{Dir: dataDir}
	key, err := ids.LoadOrCreateKey()
	if err != nil {
		return nil, fmt.Errorf("ajan anahtarı hazırlanamadı: %w", err)
	}
	csr, err := identity.NewCSR(key)
	if err != nil {
		return nil, err
	}
	c, err := client.New(cfg.ServerURL, cfg.CAHash, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Enroll(ctx, protocol.EnrollRequest{
		RegistrationKey: cfg.RegistrationKey,
		CSRPEM:          string(csr),
		Host:            hi.Collect(),
	})
	if err != nil {
		return nil, fmt.Errorf("kayıt başarısız: %w", err)
	}
	if err := ids.SaveEnrollment(resp, time.Now()); err != nil {
		return nil, err
	}
	cfg.RegistrationKey = ""
	if err := config.Save(dataDir, cfg); err != nil {
		return nil, fmt.Errorf("kayıt anahtarı yapılandırmadan silinemedi: %w", err)
	}
	st, _, err := ids.Load()
	return st, err
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*dataDir)
	if err != nil {
		return err
	}
	asService := service.IsService()
	log, closer, err := newLogger(*dataDir, cfg.LogLevel, !asService)
	if err != nil {
		return err
	}
	defer closer.Close()

	body := func(ctx context.Context) error {
		err := agentMain(ctx, *dataDir, cfg, log)
		if err != nil {
			log.Error("ajan durdu", "hata", err)
		}
		return err
	}
	if asService {
		return service.Run(body)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return body(ctx)
}

func agentMain(ctx context.Context, dataDir string, cfg config.Config, log *slog.Logger) error {
	started := time.Now().UTC()
	log.Info("ajan başlatıldı", "sürüm", version.Version, "sunucu", cfg.ServerURL, "veri_dizini", dataDir)
	hi := hostinfo.New()
	ids := identity.Store{Dir: dataDir}

	st, cert, err := ids.Load()
	for errors.Is(err, identity.ErrNotEnrolled) {
		if cfg.RegistrationKey == "" {
			return errors.New("ajan kayıtlı değil ve kayıt anahtarı yapılandırılmamış")
		}
		// Kayıt başarısız olursa (sunucu kapalı, ağ yok) üstel geri çekilmeyle yeniden denenir.
		for attempt := 1; ; attempt++ {
			_, err = enroll(ctx, dataDir, cfg, hi)
			if err == nil {
				break
			}
			wait := runner.Jitter(runner.Backoff(attempt, 30*time.Second, runner.MaxBackoff), 0.2, rand.Float64)
			log.Warn("kayıt başarısız, yeniden denenecek", "hata", err, "bekleme", wait.Round(time.Second))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
		}
		cfg.RegistrationKey = ""
		st, cert, err = ids.Load()
	}
	if err != nil {
		return err
	}
	log.Info("kimlik yüklendi", "ajan", st.AgentID, "kayıt_durumu", st.Status)

	c, err := client.New(cfg.ServerURL, cfg.CAHash, cert)
	if err != nil {
		return err
	}
	r := &runner.Runner{
		Client:    c,
		Log:       log,
		Collect:   hi.Collect,
		StartedAt: started,
		OnResponse: func(*protocol.HeartbeatResponse) {
			// Heartbeat'ler arasında soket açık tutulmaz; binlerce ajan sunucuda bağlantı biriktirmez.
			c.CloseIdle()
		},
	}
	r.Run(ctx)
	log.Info("ajan durduruldu")
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := dataDirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*dataDir)
	if err != nil {
		return err
	}
	fmt.Println("Sunucu       :", cfg.ServerURL)
	fmt.Println("CA parmak izi:", cfg.CAHash)
	st, _, err := identity.Store{Dir: *dataDir}.Load()
	if errors.Is(err, identity.ErrNotEnrolled) {
		fmt.Println("Kayıt        : yapılmamış")
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Println("Ajan ID      :", st.AgentID)
	fmt.Println("Kayıt durumu :", st.Status)
	fmt.Println("Kayıt tarihi :", st.EnrolledAt.Local().Format(time.RFC3339))
	return nil
}
