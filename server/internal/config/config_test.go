package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadFileAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ber-server.yaml")
	if err := os.WriteFile(path, []byte(`
database_url: postgres://dosya
console:
  listen: ":9443"
agent:
  hostnames: [ber.example.test]
session:
  idle_timeout: 15m
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BER_DATABASE_URL", "postgres://ortam")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseURL != "postgres://ortam" {
		t.Errorf("ortam değişkeni dosyayı geçersiz kılmalı: %s", cfg.DatabaseURL)
	}
	if cfg.Console.Listen != ":9443" || cfg.Agent.Hostnames[0] != "ber.example.test" {
		t.Errorf("dosya değerleri uygulanmalı: %+v", cfg)
	}
	if cfg.Session.IdleTimeout.D() != 15*time.Minute || cfg.Session.AbsoluteTimeout.D() != 12*time.Hour {
		t.Errorf("süreler yanlış: %+v", cfg.Session)
	}
	if cfg.Agent.HeartbeatSeconds != 60 {
		t.Errorf("belirtilmeyen alanlar varsayılanda kalmalı: %d", cfg.Agent.HeartbeatSeconds)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ber-server.yaml")
	if err := os.WriteFile(path, []byte("database_url: x\nconsle:\n  listen: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("yazım hatalı alan reddedilmeli")
	}
}

func TestValidate(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err == nil {
		t.Error("database_url olmadan hata beklenirdi")
	}
	cfg.DatabaseURL = "postgres://x"
	if err := cfg.Validate(); err != nil {
		t.Errorf("varsayılanlar geçerli olmalı: %v", err)
	}
	cfg.Console.TLSCertFile = "cert.pem"
	if err := cfg.Validate(); err == nil {
		t.Error("anahtar dosyası olmadan sertifika reddedilmeli")
	}
}
