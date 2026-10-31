package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BerkayAtag/BerOps/server/internal/store"
	"github.com/BerkayAtag/BerOps/server/internal/store/storetest"
)

func TestMigrateIsIdempotent(t *testing.T) {
	s := storetest.New(t)
	applied, err := s.Migrate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 0 {
		t.Errorf("ikinci çalıştırmada migration uygulanmamalı, %v", applied)
	}
}

func TestAuditLogIsAppendOnly(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	if err := s.AppendAudit(ctx, store.AuditEntry{
		ActorType: store.ActorSystem, Action: "test.olay", Result: store.ResultSuccess,
		Params: map[string]any{"anahtar": "değer"},
	}); err != nil {
		t.Fatal(err)
	}
	entries, _, err := s.ListAudit(ctx, store.AuditFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Params["anahtar"] != "değer" {
		t.Fatalf("beklenmeyen denetim kaydı: %+v", entries)
	}

	for _, q := range []string{
		`UPDATE audit_log SET action = 'degisti'`,
		`DELETE FROM audit_log`,
		`TRUNCATE audit_log`,
	} {
		_, err := s.ExecForTest(ctx, q)
		if err == nil || !strings.Contains(err.Error(), "yalnızca eklemeye açıktır") {
			t.Errorf("%q engellenmeliydi, hata: %v", q, err)
		}
	}
}

func TestRegistrationKeyConsumption(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	now := time.Now()
	one := 1
	k, err := s.CreateRegistrationKey(ctx, store.NewRegistrationKey{
		Name: "tek kullanımlık", KeyHash: []byte("hash-1"), KeyPrefix: "berreg_abc", MaxUses: &one,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRegistrationKey(ctx, []byte("hash-1"), now); err != nil {
		t.Fatalf("ilk kullanım başarılı olmalı: %v", err)
	}
	if _, err := s.ConsumeRegistrationKey(ctx, []byte("hash-1"), now); err != store.ErrNotFound {
		t.Errorf("kullanım hakkı bitince ErrNotFound beklenirdi, %v", err)
	}

	past := now.Add(-time.Minute)
	if _, err := s.CreateRegistrationKey(ctx, store.NewRegistrationKey{
		Name: "süresi dolmuş", KeyHash: []byte("hash-2"), KeyPrefix: "berreg_def", ExpiresAt: &past,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRegistrationKey(ctx, []byte("hash-2"), now); err != store.ErrNotFound {
		t.Errorf("süresi dolmuş anahtar reddedilmeli, %v", err)
	}

	if _, err := s.CreateRegistrationKey(ctx, store.NewRegistrationKey{
		Name: "iptal", KeyHash: []byte("hash-3"), KeyPrefix: "berreg_ghi",
	}); err != nil {
		t.Fatal(err)
	}
	keys, _ := s.ListRegistrationKeys(ctx)
	var revokeID string
	for _, kk := range keys {
		if kk.Name == "iptal" {
			revokeID = kk.ID
		}
	}
	if _, err := s.RevokeRegistrationKey(ctx, revokeID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConsumeRegistrationKey(ctx, []byte("hash-3"), now); err != store.ErrNotFound {
		t.Errorf("iptal edilmiş anahtar reddedilmeli, %v", err)
	}
	if _, err := s.ConsumeRegistrationKey(ctx, []byte("yok"), now); err != store.ErrNotFound {
		t.Errorf("olmayan anahtar ErrNotFound dönmeli, %v", err)
	}
	_ = k
}

func TestUsernameIsCaseInsensitiveUnique(t *testing.T) {
	s := storetest.New(t)
	ctx := context.Background()
	if _, err := s.CreateLocalUser(ctx, "Admin", "", "$argon2id$x", "admin", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateLocalUser(ctx, "admin", "", "$argon2id$x", "admin", false); err != store.ErrConflict {
		t.Errorf("büyük/küçük harf farkı olan aynı ad reddedilmeli, %v", err)
	}
	u, err := s.GetUserByUsername(ctx, "ADMIN")
	if err != nil || u.Username != "Admin" {
		t.Errorf("kullanıcı büyük/küçük harf duyarsız bulunmalı: %v %+v", err, u)
	}
}
