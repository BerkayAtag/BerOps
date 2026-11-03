package main

import (
	"errors"
	"testing"

	"github.com/BerkayAtag/BerOps/agent/internal/protection"
)

// Kaldırma kodu MSI komut satırına kullanıcının verdiği değerle eklenir; tırnakla eklenen
// bayrak veya argümanlar korumayı başka bir veri dizinine yöneltememelidir.
func TestUninstallCheckRejectsInjectedArguments(t *testing.T) {
	cases := [][]string{
		{"-code", "x", "-data-dir", `C:\yok`},
		{"-data-dir", "/tmp/yok"},
		{"-code", "x", "fazla"},
	}
	for _, args := range cases {
		if err := cmdUninstallCheck(args); err == nil {
			t.Errorf("%q kabul edilmemeli", args)
		}
	}
	if err := cmdUninstallCheck([]string{"-code", "x", "fazla"}); !errors.Is(err, protection.ErrWrongCode) {
		t.Errorf("fazladan argüman kod hatası vermeli: %v", err)
	}
}
