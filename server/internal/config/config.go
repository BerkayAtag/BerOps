// Package config, sunucu yapılandırmasını YAML dosyasından ve ortam değişkenlerinden okur.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Duration, YAML'da "30m", "12h" gibi yazılabilen süredir.
type Duration time.Duration

// UnmarshalYAML, süreyi metinden ayrıştırır.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("geçersiz süre %q: %w", n.Value, err)
	}
	*d = Duration(v)
	return nil
}

// D, time.Duration değerini döner.
func (d Duration) D() time.Duration { return time.Duration(d) }

// Config, sunucunun tüm yapılandırmasıdır.
type Config struct {
	// DataDir; PKI anahtarları, paket deposu ve diğer kalıcı dosyaların kök dizinidir.
	DataDir     string        `yaml:"data_dir"`
	DatabaseURL string        `yaml:"database_url"`
	LogLevel    string        `yaml:"log_level"`
	Console     ConsoleConfig `yaml:"console"`
	Agent       AgentConfig   `yaml:"agent"`
	Session     SessionConfig `yaml:"session"`
}

// ConsoleConfig, konsol (UI + API) dinleyicisinin ayarlarıdır.
type ConsoleConfig struct {
	Listen string `yaml:"listen"`
	// TLSCertFile ve TLSKeyFile boşsa iç CA'dan sertifika üretilir.
	TLSCertFile string   `yaml:"tls_cert_file"`
	TLSKeyFile  string   `yaml:"tls_key_file"`
	Hostnames   []string `yaml:"hostnames"`
	// StaticDir, derlenmiş konsol dosyalarının dizinidir. Boşsa yalnızca API sunulur.
	StaticDir string `yaml:"static_dir"`
}

// AgentConfig, ajan API'si dinleyicisinin ayarlarıdır.
type AgentConfig struct {
	Listen string `yaml:"listen"`
	// Hostnames, ajanların sunucuya bağlanırken kullandığı adlardır (sertifika SAN'ları).
	Hostnames        []string `yaml:"hostnames"`
	HeartbeatSeconds int      `yaml:"heartbeat_seconds"`
	CertValidity     Duration `yaml:"cert_validity"`
}

// SessionConfig, konsol oturum süreleridir.
type SessionConfig struct {
	IdleTimeout     Duration `yaml:"idle_timeout"`
	AbsoluteTimeout Duration `yaml:"absolute_timeout"`
}

// Default, kurulum sihirbazının da başlangıç noktası olan varsayılan yapılandırmadır.
func Default() Config {
	return Config{
		DataDir:  "data",
		LogLevel: "info",
		Console: ConsoleConfig{
			Listen:    ":8443",
			Hostnames: []string{"localhost", "127.0.0.1"},
		},
		Agent: AgentConfig{
			Listen:           ":52311",
			Hostnames:        []string{"localhost", "127.0.0.1"},
			HeartbeatSeconds: 60,
			CertValidity:     Duration(365 * 24 * time.Hour),
		},
		Session: SessionConfig{
			IdleTimeout:     Duration(30 * time.Minute),
			AbsoluteTimeout: Duration(12 * time.Hour),
		},
	}
}

// Load, varsayılanların üzerine dosyayı (varsa) ve ortam değişkenlerini uygular.
// path boşsa veya dosya yoksa yalnızca varsayılanlar ve ortam değişkenleri kullanılır.
func Load(path string) (Config, error) {
	cfg := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case err == nil:
			dec := yaml.NewDecoder(bytes.NewReader(b))
			dec.KnownFields(true)
			if err := dec.Decode(&cfg); err != nil {
				return cfg, fmt.Errorf("%s okunamadı: %w", path, err)
			}
		case errors.Is(err, os.ErrNotExist):
		default:
			return cfg, err
		}
	}
	applyEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("BER_DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := os.Getenv("BER_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("BER_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("BER_CONSOLE_STATIC_DIR"); v != "" {
		cfg.Console.StaticDir = v
	}
}

// Validate, yapılandırmanın tutarlılığını denetler.
func (c Config) Validate() error {
	var errs []error
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("database_url (veya BER_DATABASE_URL) gerekli"))
	}
	if c.DataDir == "" {
		errs = append(errs, errors.New("data_dir gerekli"))
	}
	if (c.Console.TLSCertFile == "") != (c.Console.TLSKeyFile == "") {
		errs = append(errs, errors.New("console.tls_cert_file ve console.tls_key_file birlikte verilmeli"))
	}
	if len(c.Agent.Hostnames) == 0 {
		errs = append(errs, errors.New("agent.hostnames en az bir ad içermeli"))
	}
	if c.Agent.HeartbeatSeconds < 10 {
		errs = append(errs, errors.New("agent.heartbeat_seconds en az 10 olmalı"))
	}
	if c.Session.IdleTimeout.D() <= 0 || c.Session.AbsoluteTimeout.D() < c.Session.IdleTimeout.D() {
		errs = append(errs, errors.New("session süreleri geçersiz (absolute_timeout >= idle_timeout > 0)"))
	}
	return errors.Join(errs...)
}

// PKIDir, iç CA dosyalarının dizinidir.
func (c Config) PKIDir() string { return filepath.Join(c.DataDir, "pki") }
