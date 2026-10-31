// ber-relay, şubeler için önbellekleyen dağıtım noktasıdır.
//
//	ber-relay -server https://ber.corp.example:52311 -dir /etc/ber-relay [-listen :52311] [-cache /var/cache/ber-relay] [-cache-gb 50]
//
// -dir klasöründe sunucuda "ber-server relay create" ile üretilen relay.crt, relay.key ve ca.crt bulunur.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/BerkayAtag/automation-ber/relay/relay"
	"github.com/BerkayAtag/automation-ber/shared/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hata:", err)
		os.Exit(1)
	}
}

func run() error {
	server := flag.String("server", "", "BER sunucusunun ajan adresi (https://sunucu:52311)")
	dir := flag.String("dir", ".", "relay.crt, relay.key ve ca.crt dosyalarının klasörü")
	listen := flag.String("listen", ":52311", "ajanların bağlanacağı adres")
	cacheDir := flag.String("cache", "cache", "paket önbelleği klasörü")
	cacheGB := flag.Int("cache-gb", 50, "önbellek üst sınırı (GB)")
	showVersion := flag.Bool("version", false, "sürümü yazdır")
	flag.Parse()
	if *showVersion {
		fmt.Printf("ber-relay %s (%s)\n", version.Version, version.Commit)
		return nil
	}
	if *server == "" {
		return errors.New("-server gerekli")
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ca, err := relay.LoadCA(filepath.Join(*dir, "ca.crt"))
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(*dir, "relay.crt"), filepath.Join(*dir, "relay.key"))
	if err != nil {
		return fmt.Errorf("relay sertifikası yüklenemedi: %w", err)
	}
	r, err := relay.New(relay.Config{ServerURL: *server, CA: ca, Cert: cert, CacheDir: *cacheDir,
		CacheBytes: int64(*cacheGB) << 30, Log: log})
	if err != nil {
		return err
	}
	hs := &http.Server{
		Addr: *listen, Handler: r, TLSConfig: r.TLSConfig(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 5 * time.Minute,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() {
		log.Info("relay dinleniyor", "adres", *listen, "sunucu", *server, "adlar", relay.HostsOf(cert), "sürüm", version.Version)
		errc <- hs.ListenAndServeTLS("", "")
	}()
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}
