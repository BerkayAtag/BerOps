package simdata

import (
	"testing"

	"github.com/BerkayAtag/automation-ber/shared/protocol"
)

func TestGenerateIsDeterministicAndValid(t *testing.T) {
	p := Profile{Platform: "windows", Name: "Windows 11 Pro", Version: "23H2", Build: "10.0.22631.4460", Arch: "amd64"}
	a, b := Generate(7, p, true), Generate(7, p, true)
	if protocol.HashSection(a.Apps) != protocol.HashSection(b.Apps) || protocol.HashSection(a.MissingPatches) != protocol.HashSection(b.MissingPatches) {
		t.Error("aynı ajan aynı envanteri üretmeli")
	}
	if len(a.Apps) == 0 || a.OS.ADDN == "" || !a.Collected["missing_patches"] {
		t.Errorf("eksik envanter: %+v", a.OS)
	}
	mac := Generate(8, Profile{Platform: "darwin", Name: "macOS", Version: "15.1", Build: "24B83", Arch: "arm64"}, false)
	if mac.Collected["missing_patches"] || mac.OS.Manufacturer != "Apple" {
		t.Errorf("macOS profili: %+v", mac.OS)
	}
}
