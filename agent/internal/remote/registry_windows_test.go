//go:build windows

package remote

import (
	"testing"

	"golang.org/x/sys/windows/registry"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func TestRegistryRoundTrip(t *testing.T) {
	const path = `HKLM\SOFTWARE\AutomationBERTest`
	t.Cleanup(func() { _ = registry.DeleteKey(registry.LOCAL_MACHINE, `SOFTWARE\AutomationBERTest`) })
	ch, err := RegistrySet(path, protocol.RegistryValue{Name: "Sürüm", Type: "REG_SZ", Data: "1.0 ğüş"})
	if err != nil {
		t.Skipf("HKLM'ye yazılamadı (yönetici değil?): %v", err)
	}
	if ch.Previous != nil {
		t.Errorf("yeni değerin önceki değeri olmamalı: %+v", ch.Previous)
	}
	if _, err := RegistrySet(path, protocol.RegistryValue{Name: "Sayaç", Type: "REG_DWORD", Data: "0x2A"}); err != nil {
		t.Fatal(err)
	}
	ch, err = RegistrySet(path, protocol.RegistryValue{Name: "Sürüm", Type: "REG_SZ", Data: "2.0"})
	if err != nil || ch.Previous == nil || ch.Previous.Data != "1.0 ğüş" {
		t.Fatalf("önceki değer dönmeli: %+v %v", ch, err)
	}
	key, err := RegistryList(path)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]protocol.RegistryValue{}
	for _, v := range key.Values {
		got[v.Name] = v
	}
	if got["Sayaç"].Data != "42" || got["Sayaç"].Type != "REG_DWORD" || got["Sürüm"].Data != "2.0" {
		t.Errorf("değerler = %+v", key.Values)
	}
	if _, err := RegistryDelete(path, "Sayaç"); err != nil {
		t.Fatal(err)
	}
	if root, err := RegistryList(`HKLM\SOFTWARE`); err != nil || len(root.Subkeys) == 0 {
		t.Errorf("HKLM\\SOFTWARE listelenemedi: %v", err)
	}
	if _, err := RegistryList(`HKXX\Yok`); err == nil {
		t.Error("geçersiz kök reddedilmeli")
	}
}
