package auth

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAndVerify(t *testing.T) {
	h, err := HashPassword("doğru-parola-123")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$") {
		t.Fatalf("beklenmeyen özet biçimi: %s", h)
	}
	if err := VerifyPassword(h, "doğru-parola-123"); err != nil {
		t.Errorf("doğru parola kabul edilmeli: %v", err)
	}
	if err := VerifyPassword(h, "yanlış-parola-123"); err != ErrPasswordMismatch {
		t.Errorf("yanlış parola ErrPasswordMismatch dönmeli, %v döndü", err)
	}
	h2, _ := HashPassword("doğru-parola-123")
	if h == h2 {
		t.Error("aynı parola için tuz farklı olmalı")
	}
}

func TestVerifyPasswordRejectsMalformed(t *testing.T) {
	for _, enc := range []string{"", "düz-metin", "$bcrypt$x$y$z$w", "$argon2id$v=19$m=x$a$b"} {
		if err := VerifyPassword(enc, "x"); err == nil || err == ErrPasswordMismatch {
			t.Errorf("%q biçim hatası vermeli, %v döndü", enc, err)
		}
	}
}

func TestPasswordPolicy(t *testing.T) {
	if err := ValidatePasswordPolicy("kısa"); err == nil {
		t.Error("kısa parola reddedilmeli")
	}
	if err := ValidatePasswordPolicy("yeterince-uzun-parola"); err != nil {
		t.Errorf("uzun parola kabul edilmeli: %v", err)
	}
}

func TestTokensAreUniqueAndHashed(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == b || len(a) < 40 {
		t.Fatalf("token'lar benzersiz ve uzun olmalı: %q %q", a, b)
	}
	if string(HashToken(a)) == a || len(HashToken(a)) != 32 {
		t.Error("token özeti 32 bayt SHA-256 olmalı")
	}
	key, prefix, err := NewRegistrationKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, RegistrationKeyPrefix) || !strings.HasPrefix(key, prefix) {
		t.Errorf("kayıt anahtarı önekle başlamalı: %q / %q", key, prefix)
	}
}

func TestAttemptLimiter(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	l := NewAttemptLimiter(3, 10*time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allowed("ip"); !ok {
			t.Fatalf("%d. denemeye izin verilmeli", i+1)
		}
		l.Fail("ip")
		now = now.Add(time.Minute)
	}
	ok, wait := l.Allowed("ip")
	if ok {
		t.Fatal("3 başarısız denemeden sonra engellenmeli")
	}
	if wait != 7*time.Minute {
		t.Errorf("bekleme süresi 7 dk olmalı, %v", wait)
	}
	if ok, _ := l.Allowed("baska-ip"); !ok {
		t.Error("diğer anahtarlar etkilenmemeli")
	}

	now = now.Add(7 * time.Minute)
	if ok, _ := l.Allowed("ip"); !ok {
		t.Error("en eski deneme pencereden çıkınca izin verilmeli")
	}

	l.Fail("ip")
	l.Reset("ip")
	if ok, _ := l.Allowed("ip"); !ok {
		t.Error("Reset sonrası izin verilmeli")
	}

	l.Fail("eski")
	now = now.Add(time.Hour)
	l.Sweep()
	if _, exists := l.failures["eski"]; exists {
		t.Error("Sweep süresi dolan kayıtları silmeli")
	}
}

// Spesifikasyon §7.2: Teknisyen yalnızca kayıtlı paket gönderebilir; Salt Okunur hiçbir
// değişiklik yapamaz. Bu test, rollerin izin kümesini tam olarak sabitler.
func TestRolePermissions(t *testing.T) {
	writePerms := []Permission{
		PermMachinesManage, PermPackagesUpload, PermPackagesDelete,
		PermActionsDeployPatch, PermActionsRunCommand, PermActionsApprove,
		PermRemotePerformance, PermRemoteServices, PermRemoteRegistryRead, PermRemoteRegistryWrite, PermRemoteSettings,
		PermSettingsWrite, PermUsersManage, PermADConfigure, PermRegKeysManage, PermRateLimitManage,
	}

	for _, p := range AllPermissions {
		if !HasPermission(RoleAdmin, p) {
			t.Errorf("admin %s iznine sahip olmalı", p)
		}
	}
	for _, p := range readPermissions {
		for _, r := range []Role{RoleAdmin, RoleTechnician, RoleReadOnly} {
			if !HasPermission(r, p) {
				t.Errorf("%s okuma izni %s'e sahip olmalı", r, p)
			}
		}
	}
	for _, p := range writePerms {
		if HasPermission(RoleTechnician, p) {
			t.Errorf("teknisyen %s iznine sahip olmamalı", p)
		}
		if HasPermission(RoleReadOnly, p) {
			t.Errorf("salt okunur %s iznine sahip olmamalı", p)
		}
	}
	if !HasPermission(RoleTechnician, PermActionsDeployPackage) {
		t.Error("teknisyen kayıtlı paket gönderebilmeli")
	}
	if HasPermission(RoleReadOnly, PermActionsDeployPackage) {
		t.Error("salt okunur paket gönderememeli")
	}
	if HasPermission(Role("bilinmeyen"), PermMachinesRead) {
		t.Error("bilinmeyen rol hiçbir izne sahip olmamalı")
	}
	if got := len(writePerms) + len(readPermissions) + 1; got != len(AllPermissions) {
		t.Errorf("tüm izinler bu testte sınıflandırılmalı: %d / %d", got, len(AllPermissions))
	}
}
