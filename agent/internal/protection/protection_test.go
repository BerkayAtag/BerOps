package protection

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/BerkayAtag/BerOps/shared/protocol"
)

func TestApplyAndCheck(t *testing.T) {
	dir := t.TempDir()
	if err := Check(dir, ""); err != nil {
		t.Fatalf("koruma yokken kaldırma serbest olmalı: %v", err)
	}
	salt := []byte("0123456789abcdef")
	hash, err := protocol.HashUninstallCode("Gizli-Kod-42", salt, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	p := &protocol.UninstallProtection{Enabled: true, Salt: salt, Hash: hash, Iterations: 10_000}
	if changed, err := Apply(dir, p); err != nil || !changed {
		t.Fatalf("Apply = %v, %v", changed, err)
	}
	if changed, _ := Apply(dir, p); changed {
		t.Fatal("aynı ayar ikinci kez yazılmamalı")
	}
	if err := Check(dir, ""); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("kodsuz kaldırma reddedilmeli: %v", err)
	}
	if err := Check(dir, "yanlis"); !errors.Is(err, ErrWrongCode) {
		t.Fatalf("yanlış kod reddedilmeli: %v", err)
	}
	if err := Check(dir, "Gizli-Kod-42"); err != nil {
		t.Fatalf("doğru kod kabul edilmeli: %v", err)
	}
	if changed, err := Apply(dir, &protocol.UninstallProtection{Enabled: false}); err != nil || !changed {
		t.Fatalf("kapatma = %v, %v", changed, err)
	}
	if err := Check(dir, ""); err != nil {
		t.Fatalf("koruma kapatılınca kaldırma serbest olmalı: %v", err)
	}
}

func TestCorruptFileDenies(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir, "{bozuk"); err != nil {
		t.Fatal(err)
	}
	if err := Check(dir, "x"); err == nil {
		t.Fatal("okunamayan koruma dosyasında kaldırma reddedilmeli")
	}
}

func writeFile(dir, body string) error {
	return os.WriteFile(filepath.Join(dir, FileName), []byte(body), 0o600)
}
