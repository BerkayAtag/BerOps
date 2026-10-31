package secret

import (
	"bytes"
	"errors"
	"testing"
)

func TestSealOpen(t *testing.T) {
	dir := t.TempDir()
	b1, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := b1.Seal([]byte("gizli-parola-ğüş"), "ad.bind")
	if err != nil || bytes.Contains(sealed, []byte("gizli")) {
		t.Fatalf("şifreleme: %v", err)
	}
	b2, _ := LoadOrCreate(dir)
	got, err := b2.Open(sealed, "ad.bind")
	if err != nil || string(got) != "gizli-parola-ğüş" {
		t.Fatalf("aynı anahtarla çözülmeli: %v", err)
	}
	if _, err := b2.Open(sealed, "baska.alan"); !errors.Is(err, ErrDecrypt) {
		t.Error("farklı etiketle çözülmemeli")
	}
	if _, err := NewRandom().Open(sealed, "ad.bind"); !errors.Is(err, ErrDecrypt) {
		t.Error("farklı anahtarla çözülmemeli")
	}
}
