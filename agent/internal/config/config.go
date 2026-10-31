// Package config, ajanın yerel yapılandırmasını (agent.yaml) okur ve yazar.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// FileName, veri dizinindeki yapılandırma dosyasının adıdır.
const FileName = "agent.yaml"

// Config, ajan yapılandırmasıdır. MSI/pkg kurulumu SERVER, REGKEY ve CAHASH
// parametrelerini bu dosyaya yazar.
type Config struct {
	ServerURL string `yaml:"server_url"`
	CAHash    string `yaml:"ca_hash"`
	// RegistrationKey, yalnızca ilk kayıt için kullanılır ve başarılı kayıttan sonra silinir.
	RegistrationKey string `yaml:"registration_key,omitempty"`
	LogLevel        string `yaml:"log_level,omitempty"`
}

// Load, dir içindeki yapılandırmayı okur.
// ErrNotConfigured, yapılandırma dosyası henüz yazılmamış ajanı belirtir (ör. kurulum paketi
// anahtarsız kuruldu, yapılandırma daha sonra GPO/MDM ile gelecek).
var ErrNotConfigured = errors.New("ajan yapılandırılmamış")

func Load(dir string) (Config, error) {
	var c Config
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if errors.Is(err, os.ErrNotExist) {
		return c, fmt.Errorf("%w (%s yok); önce 'ber-agent enroll' veya 'ber-agent configure' çalıştırın",
			ErrNotConfigured, filepath.Join(dir, FileName))
	}
	if err != nil {
		return c, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("%s okunamadı: %w", FileName, err)
	}
	return c, c.Validate()
}

// Save, yapılandırmayı yalnızca servis hesabının okuyabileceği izinlerle yazar.
func Save(dir string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, FileName+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, FileName))
}

// Validate, zorunlu alanları denetler.
func (c Config) Validate() error {
	u, err := url.Parse(c.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("server_url https://sunucu:port biçiminde olmalı: %q", c.ServerURL)
	}
	if c.CAHash == "" {
		return errors.New("ca_hash (CA parmak izi) gerekli")
	}
	return nil
}
