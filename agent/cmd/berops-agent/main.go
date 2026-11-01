// berops-agent, BerOps istemci ajanıdır (Windows servisi / macOS launchd daemon'ı).
//
//	berops-agent configure -server https://ber.example.test:52311 -key berreg_... -ca-hash sha256:...
//	berops-agent enroll    -server https://ber.example.test:52311 -key berreg_... -ca-hash sha256:...
//	berops-agent run
//	berops-agent status
//	berops-agent version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/BerkayAtag/BerOps/agent/internal/client"
	"github.com/BerkayAtag/BerOps/agent/internal/config"
	"github.com/BerkayAtag/BerOps/agent/internal/hostinfo"
	"github.com/BerkayAtag/BerOps/agent/internal/identity"
	"github.com/BerkayAtag/BerOps/agent/internal/inventory"
	"github.com/BerkayAtag/BerOps/agent/internal/jobs"
	"github.com/BerkayAtag/BerOps/agent/internal/paths"
	"github.com/BerkayAtag/BerOps/agent/internal/remote"
	"github.com/BerkayAtag/BerOps/agent/internal/runner"
	"github.com/BerkayAtag/BerOps/agent/internal/scanner"
	"github.com/BerkayAtag/BerOps/agent/internal/sysres"
	"github.com/BerkayAtag/BerOps/shared/protocol"
	"github.com/BerkayAtag/BerOps/shared/service"
	"github.com/BerkayAtag/BerOps/shared/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Kullanım: berops-agent <komut> [seçenekler]

Komutlar:
  run        Ajanı çalıştırır (servis olarak ya da ön planda)
  configure  Sunucu adresini, kayıt anahtarını ve CA parmak izini kaydeder (kayıt servis başlayınca yapılır)
  enroll     Yapılandırmayı kaydeder ve hemen kaydolur
  status     Kayıt durumunu gösterir
  inventory  Envanteri bu makinede toplar ve yazdırır (sunucuya göndermez)
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
	case "inventory":
		return cmdInventory(args)
	case "version":
		fmt.Printf("berops-agent %s (%s)\n", version.Version, version.Commit)
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

// agentLogFile, veri dizinindeki logs/ altında ajanın günlük dosyasının adıdır.
const agentLogFile = "agent.log"

// newLogger, döngüsel log dosyasına (10 MB × 5) ve ön planda çalışırken stderr'e yazar.
func newLogger(dataDir, level string, foreground bool) (*slog.Logger, io.Closer, error) {
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		return nil, nil, err
	}
	lj := &lumberjack.Logger{
		Filename:   filepath.Join(logDir, agentLogFile),
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
	// Yapılandırılmamış ajan çıkmaz, yapılandırmayı bekler: kurulum paketi anahtarsız
	// kurulduğunda servis yine başlar ve yapılandırma sonradan yazılabilir.
	if err != nil && !errors.Is(err, config.ErrNotConfigured) {
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
		return service.Run(service.AgentName, body)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return body(ctx)
}

// configPollInterval, kayıt anahtarı beklenirken yapılandırmanın yeniden okunma aralığıdır.
var configPollInterval = 30 * time.Second

// waitForRegistrationKey, kayıt anahtarı içeren bir yapılandırma yazılana kadar bekler.
// Bağlam iptal edilirse boş yapılandırmayla döner.
func waitForRegistrationKey(ctx context.Context, dataDir string, log *slog.Logger) (config.Config, error) {
	log.Warn("ajan kayıtlı değil ve kayıt anahtarı yok; yapılandırma bekleniyor",
		"komut", "berops-agent configure -server <adres> -key <anahtar> -ca-hash <parmak izi>")
	for {
		select {
		case <-ctx.Done():
			return config.Config{}, nil
		case <-time.After(configPollInterval):
		}
		cfg, err := config.Load(dataDir)
		switch {
		case err == nil && cfg.RegistrationKey != "":
			log.Info("yapılandırma bulundu, kayıt deneniyor", "sunucu", cfg.ServerURL)
			return cfg, nil
		case err != nil && !errors.Is(err, config.ErrNotConfigured):
			return cfg, err
		}
	}
}

func agentMain(ctx context.Context, dataDir string, cfg config.Config, log *slog.Logger) error {
	started := time.Now().UTC()
	log.Info("ajan başlatıldı", "sürüm", version.Version, "sunucu", cfg.ServerURL, "veri_dizini", dataDir)
	hi := hostinfo.New()
	ids := identity.Store{Dir: dataDir}

	st, cert, err := ids.Load()
	for errors.Is(err, identity.ErrNotEnrolled) {
		if cfg.RegistrationKey == "" {
			if cfg, err = waitForRegistrationKey(ctx, dataDir, log); err != nil || ctx.Err() != nil {
				return err
			}
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
	if err := sysres.LowerProcessPriority(); err != nil {
		log.Warn("süreç önceliği düşürülemedi", "hata", err)
	}

	sc := scanner.New(filepath.Join(dataDir, "inventory"), runtime.GOOS, c, log)
	sc.OnBattery = sysres.OnBattery
	sc.UserActive = sysres.UserActive
	if err := sc.Load(); err != nil {
		log.Error("envanter durumu yüklenemedi", "hata", err)
	}
	go sc.Run(ctx)

	jr := jobs.New(filepath.Join(dataDir, "jobs"), c, log, st.AgentID, ids.ActionKey)
	jr.LogFile = filepath.Join(dataDir, "logs", agentLogFile)
	jr.OnFinished = func(j *protocol.Job) {
		// Yama kurulumundan sonra eksik yama listesi de yenilenmeli: tam tarama.
		if j.Kind == protocol.JobDeployPatch {
			sc.RequestFullScan()
			return
		}
		sc.RequestDeltaScan()
	}
	go jr.Run(ctx)

	rs := remote.New(c, log, st.AgentID, ids.ActionKey)

	keyWarned := false
	r := &runner.Runner{
		Client:          c,
		Log:             log,
		Collect:         hi.Collect,
		StartedAt:       started,
		InventoryHashes: sc.UploadedHashes,
		OnResponse: func(resp *protocol.HeartbeatResponse) {
			sc.ApplyHeartbeat(resp)
			if len(resp.ActionKey) > 0 {
				if err := ids.PinActionKey(resp.ActionKey); err != nil && !keyWarned {
					// Anahtar uyuşmazsa sabitlenen anahtar korunur; yeni anahtarla imzalı işler çalışmaz.
					log.Error("aksiyon imza anahtarı kabul edilmedi", "hata", err)
					keyWarned = true
				}
			}
			jr.Notify(resp.PendingJobs)
			rs.Apply(ctx, resp)
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

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	full := fs.Bool("full", false, "eksik yama taramasını da yap (Windows Update / softwareupdate; yavaş olabilir)")
	asJSON := fs.Bool("json", false, "sonucu JSON olarak yazdır")
	cpu := fs.Int("cpu-limit", 10, "tarama sırasında CPU üst sınırı (yüzde)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_ = sysres.LowerProcessPriority()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	snap := inventory.Collect(ctx, inventory.Options{CPULimitPercent: *cpu, IncludeMissing: *full})
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(snap)
	}
	if snap.OS != nil {
		fmt.Printf("İşletim sistemi : %s %s (yama seviyesi %s, %s)\n", snap.OS.Name, snap.OS.Version, snap.OS.Build, snap.OS.Arch)
		if snap.OS.Model != "" {
			fmt.Printf("Donanım         : %s %s\n", snap.OS.Manufacturer, snap.OS.Model)
		}
		if snap.OS.ADDN != "" {
			fmt.Printf("AD konumu       : %s\n", snap.OS.ADDN)
		}
		fmt.Printf("Yeniden başlatma: %v\n", snap.OS.RebootPending)
	}
	fmt.Printf("Uygulama        : %d\n", len(snap.Apps))
	fmt.Printf("Kurulu yama     : %d\n", len(snap.InstalledPatches))
	if *full {
		fmt.Printf("Eksik yama      : %d\n", len(snap.MissingPatches))
		for _, p := range snap.MissingPatches {
			fmt.Printf("  - %s %s %s\n", p.Title, p.KB, strings.Join(p.CVEs, ","))
		}
	}
	fmt.Printf("Süre            : %v\n", snap.Duration.Round(time.Millisecond))
	for _, e := range snap.Errors {
		fmt.Println("Hata            :", e)
	}
	return nil
}
