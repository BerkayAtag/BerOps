package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

func TestSignedJobVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	job := Job{ID: "a1", Kind: JobRunCommand, MachineID: "m1", IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		TimeoutSeconds: 60, Shell: ShellPowerShell, Command: "Get-Date"}
	sj, err := SignJob(priv, job)
	if err != nil {
		t.Fatal(err)
	}
	if j, err := sj.Verify(pub, "m1", now); err != nil || j.Command != "Get-Date" {
		t.Fatalf("geçerli iş reddedildi: %v", err)
	}
	cases := []struct {
		name string
		mut  func(SignedJob) SignedJob
		pub  ed25519.PublicKey
		mid  string
		at   time.Time
		want error
	}{
		{"başka anahtar", func(s SignedJob) SignedJob { return s }, otherPub, "m1", now, ErrBadSignature},
		{"değiştirilmiş komut", func(s SignedJob) SignedJob {
			p := append([]byte{}, s.Payload...)
			p[len(p)-3] ^= 1
			return SignedJob{Payload: p, Signature: s.Signature}
		}, pub, "m1", now, ErrBadSignature},
		{"başka makine", func(s SignedJob) SignedJob { return s }, pub, "m2", now, ErrWrongMachine},
		{"süresi dolmuş", func(s SignedJob) SignedJob { return s }, pub, "m1", now.Add(2 * time.Hour), ErrJobExpired},
	}
	for _, c := range cases {
		if _, err := c.mut(sj).Verify(c.pub, c.mid, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, beklenen %v", c.name, err, c.want)
		}
	}
	bad, _ := SignJob(priv, Job{ID: "a2", Kind: JobDeployPackage, MachineID: "m1", ExpiresAt: now.Add(time.Hour), TimeoutSeconds: 60})
	if _, err := bad.Verify(pub, "m1", now); !errors.Is(err, ErrInvalidJobDef) {
		t.Errorf("paketsiz dağıtım işi reddedilmeli: %v", err)
	}
}

func TestValidShell(t *testing.T) {
	if !ValidShell(PlatformWindows, ShellPowerShell) || ValidShell(PlatformWindows, ShellZsh) || !ValidShell(PlatformDarwin, ShellZsh) {
		t.Error("kabuk doğrulaması hatalı")
	}
}
