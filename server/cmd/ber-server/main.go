// ber-server, Automation BER merkezi sunucusudur.
//
//	ber-server serve        -config ber-server.yaml
//	ber-server migrate      -config ber-server.yaml
//	ber-server admin create -config ber-server.yaml -username admin [-role admin] [-recovery]
//	ber-server regkey create -config ber-server.yaml -name "Pilot" [-approval] [-max-uses 10] [-expires-hours 72]
//	ber-server cve sync     -config ber-server.yaml [-feeds kev,epss,msrc,nvd]
//	ber-server version
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // raporlarda kullanıcının saat dilimi (Windows sunucularda tz veritabanı yoktur)

	"golang.org/x/term"

	"github.com/BerkayAtag/automation-ber/server/internal/api"
	"github.com/BerkayAtag/automation-ber/server/internal/auth"
	"github.com/BerkayAtag/automation-ber/server/internal/config"
	"github.com/BerkayAtag/automation-ber/server/internal/cve"
	"github.com/BerkayAtag/automation-ber/server/internal/pki"
	"github.com/BerkayAtag/automation-ber/server/internal/store"
	"github.com/BerkayAtag/automation-ber/server/internal/vuln"
	"github.com/BerkayAtag/automation-ber/shared/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Kullanım: ber-server <komut> [seçenekler]

Komutlar:
  serve          Sunucuyu başlatır (varsayılan)
  migrate        Veritabanı migration'larını uygular
  admin create   Yerel kullanıcı oluşturur (parola BER_ADMIN_PASSWORD'dan veya terminalden okunur)
  regkey create  Ajan kayıt anahtarı oluşturur
  cve sync       CVE kaynaklarını (KEV, EPSS, MSRC, NVD) hemen eşitler ve bulguları yeniden hesaplar
  version        Sürümü yazdırır

Her komut için ayrıntı: ber-server <komut> -h
`)
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "serve":
		return cmdServe(args)
	case "migrate":
		return cmdMigrate(args)
	case "admin":
		if len(args) == 0 || args[0] != "create" {
			return errors.New("kullanım: ber-server admin create -username <ad>")
		}
		return cmdAdminCreate(args[1:])
	case "regkey":
		if len(args) == 0 || args[0] != "create" {
			return errors.New("kullanım: ber-server regkey create -name <ad>")
		}
		return cmdRegKeyCreate(args[1:])
	case "cve":
		if len(args) == 0 || args[0] != "sync" {
			return errors.New("kullanım: ber-server cve sync [-feeds kev,epss,msrc,nvd]")
		}
		return cmdCVESync(args[1:])
	case "version":
		fmt.Printf("ber-server %s (%s)\n", version.Version, version.Commit)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("bilinmeyen komut: %s", cmd)
	}
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func loadConfig(fs *flag.FlagSet, args []string) (config.Config, error) {
	path := fs.String("config", "ber-server.yaml", "yapılandırma dosyası")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return config.Load(*path)
}

func openStore(ctx context.Context, cfg config.Config) (*store.Store, error) {
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if _, err := st.Migrate(ctx); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

func cmdServe(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("serve", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	applied, err := st.Migrate(ctx)
	if err != nil {
		return err
	}
	for _, m := range applied {
		log.Info("migration uygulandı", "migration", m)
	}

	ca, err := pki.LoadOrCreateCA(cfg.PKIDir(), "Automation BER Root CA")
	if err != nil {
		return err
	}
	log.Info("iç CA hazır", "parmak_izi", ca.Fingerprint())

	srv, err := api.New(cfg, st, ca, log)
	if err != nil {
		return err
	}
	signKey, err := pki.LoadOrCreateSigningKey(cfg.PKIDir())
	if err != nil {
		return fmt.Errorf("aksiyon imza anahtarı hazırlanamadı: %w", err)
	}
	srv.SetSigningKey(signKey)

	agentCert, err := ca.IssueServerCert(cfg.Agent.Hostnames, 90*24*time.Hour)
	if err != nil {
		return err
	}
	consoleCert, err := consoleCertificate(cfg, ca)
	if err != nil {
		return err
	}

	servers := []*http.Server{
		{
			Addr:              cfg.Console.Listen,
			Handler:           srv.ConsoleHandler(),
			TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{consoleCert}},
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       120 * time.Second,
		},
		{
			Addr:              cfg.Agent.Listen,
			Handler:           srv.AgentHandler(),
			TLSConfig:         srv.AgentTLSConfig(agentCert),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      120 * time.Second,
			IdleTimeout:       5 * time.Minute,
		},
	}

	go srv.RunMaintenance(ctx, 10*time.Minute)
	srv.RunBackground(ctx)

	errc := make(chan error, len(servers))
	for _, hs := range servers {
		go func(hs *http.Server) {
			log.Info("dinleniyor", "adres", hs.Addr)
			if err := hs.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", hs.Addr, err)
			}
		}(hs)
	}

	select {
	case <-ctx.Done():
		log.Info("kapatılıyor")
	case err := <-errc:
		stop()
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, hs := range servers {
		_ = hs.Shutdown(shutdownCtx)
	}
	return nil
}

// consoleCertificate, yapılandırılmış sertifikayı yükler; yoksa iç CA'dan üretir.
// İç CA'dan üretilen sertifikaya tarayıcıların güvenmesi için CA'nın (data/pki/ca.crt)
// yönetici bilgisayarlarına dağıtılması gerekir.
func consoleCertificate(cfg config.Config, ca *pki.CA) (tls.Certificate, error) {
	if cfg.Console.TLSCertFile != "" {
		c, err := tls.LoadX509KeyPair(cfg.Console.TLSCertFile, cfg.Console.TLSKeyFile)
		if err != nil {
			return c, fmt.Errorf("konsol sertifikası yüklenemedi: %w", err)
		}
		return c, nil
	}
	return ca.IssueServerCert(cfg.Console.Hostnames, 90*24*time.Hour)
}

func cmdMigrate(args []string) error {
	cfg, err := loadConfig(flag.NewFlagSet("migrate", flag.ExitOnError), args)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	applied, err := st.Migrate(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Println("Veritabanı güncel.")
	}
	for _, m := range applied {
		fmt.Println("Uygulandı:", m)
	}
	return nil
}

func readPassword() (string, error) {
	if p := os.Getenv("BER_ADMIN_PASSWORD"); p != "" {
		return p, nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", errors.New("parola okunamadı (BER_ADMIN_PASSWORD veya standart girdi)")
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "Parola: ")
	p1, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	fmt.Fprint(os.Stderr, "Parola (tekrar): ")
	p2, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", errors.New("parolalar eşleşmiyor")
	}
	return string(p1), nil
}

func cmdAdminCreate(args []string) error {
	fs := flag.NewFlagSet("admin create", flag.ExitOnError)
	username := fs.String("username", "", "kullanıcı adı (zorunlu)")
	displayName := fs.String("display-name", "", "görünen ad")
	role := fs.String("role", string(auth.RoleAdmin), "rol: admin, technician, readonly")
	recovery := fs.Bool("recovery", false, "kurtarma admin hesabı olarak işaretle")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*username) == "" {
		return errors.New("-username gerekli")
	}
	if !auth.ValidRole(auth.Role(*role)) {
		return fmt.Errorf("geçersiz rol: %s", *role)
	}
	password, err := readPassword()
	if err != nil {
		return err
	}
	if err := auth.ValidatePasswordPolicy(password); err != nil {
		return err
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	u, err := st.CreateLocalUser(ctx, strings.TrimSpace(*username), *displayName, hash, *role, *recovery)
	if errors.Is(err, store.ErrConflict) {
		return fmt.Errorf("%q kullanıcısı zaten var", *username)
	}
	if err != nil {
		return err
	}
	_ = st.AppendAudit(ctx, store.AuditEntry{
		ActorType: store.ActorSystem, ActorName: "ber-server cli", Action: "user.create",
		TargetType: "user", TargetID: u.ID, Result: store.ResultSuccess,
		Params: map[string]any{"username": u.Username, "role": u.Role, "recovery": u.IsRecovery},
	})
	fmt.Printf("Kullanıcı oluşturuldu: %s (%s)\n", u.Username, u.Role)
	return nil
}

func cmdRegKeyCreate(args []string) error {
	fs := flag.NewFlagSet("regkey create", flag.ExitOnError)
	name := fs.String("name", "", "anahtar adı (zorunlu)")
	approval := fs.Bool("approval", false, "kayıt yönetici onayı gerektirsin")
	maxUses := fs.Int("max-uses", 0, "en fazla kullanım sayısı (0 = sınırsız)")
	expiresHours := fs.Int("expires-hours", 0, "geçerlilik süresi, saat (0 = süresiz)")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return errors.New("-name gerekli")
	}
	secret, prefix, err := auth.NewRegistrationKey()
	if err != nil {
		return err
	}
	n := store.NewRegistrationKey{
		Name: *name, KeyHash: auth.HashToken(secret), KeyPrefix: prefix, RequireApproval: *approval,
	}
	if *maxUses > 0 {
		n.MaxUses = maxUses
	}
	if *expiresHours > 0 {
		t := time.Now().Add(time.Duration(*expiresHours) * time.Hour)
		n.ExpiresAt = &t
	}
	ctx := context.Background()
	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	ca, err := pki.LoadOrCreateCA(cfg.PKIDir(), "Automation BER Root CA")
	if err != nil {
		return err
	}
	k, err := st.CreateRegistrationKey(ctx, n)
	if err != nil {
		return err
	}
	_ = st.AppendAudit(ctx, store.AuditEntry{
		ActorType: store.ActorSystem, ActorName: "ber-server cli", Action: "regkey.create",
		TargetType: "registration_key", TargetID: k.ID, Result: store.ResultSuccess,
		Params: map[string]any{"name": k.Name, "require_approval": k.RequireApproval},
	})
	fmt.Printf("Kayıt anahtarı oluşturuldu: %s\n\n", k.Name)
	fmt.Printf("  Anahtar       : %s\n", secret)
	fmt.Printf("  CA parmak izi : %s\n\n", ca.Fingerprint())
	fmt.Println("Anahtar yalnızca şimdi gösterilir; güvenli bir yerde saklayın.")
	return nil
}

func cmdCVESync(args []string) error {
	fs := flag.NewFlagSet("cve sync", flag.ExitOnError)
	feeds := fs.String("feeds", strings.Join(cve.AllFeeds, ","), "eşitlenecek kaynaklar")
	cfg, err := loadConfig(fs, args)
	if err != nil {
		return err
	}
	var list []string
	for _, f := range strings.Split(*feeds, ",") {
		if f = strings.TrimSpace(f); f != "" {
			list = append(list, f)
		}
	}
	log := newLogger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	st, err := openStore(ctx, cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	if _, err := st.Migrate(ctx); err != nil {
		return err
	}
	eng, err := vuln.New(ctx, st, log)
	if err != nil {
		return err
	}
	syncer := &cve.Syncer{
		Store: st, Log: log, Products: eng.TrackedProducts, NVDAPIKey: cfg.CVE.NVDAPIKey,
		MSRCMonths: cfg.CVE.MSRCMonths, OfflineDir: cfg.CVE.OfflineDir,
	}
	syncErr := syncer.Sync(ctx, list...)
	eng.RecomputeAll()
	if err := eng.Flush(ctx); err != nil {
		return errors.Join(syncErr, err)
	}
	return syncErr
}
