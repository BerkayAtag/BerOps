// Package storetest, entegrasyon testleri için her teste ayrı, geçici bir PostgreSQL
// veritabanı oluşturur. BER_TEST_DATABASE_URL tanımlı değilse test atlanır.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/BerkayAtag/BerOps/server/internal/store"
)

// EnvVar, test veritabanı sunucusunun adresini taşıyan ortam değişkenidir.
// Örnek: postgres://ber:ber@localhost:5432/postgres?sslmode=disable
const EnvVar = "BER_TEST_DATABASE_URL"

// New, migration'ları uygulanmış boş bir veritabanı döner; test bitince veritabanı silinir.
func New(t *testing.T) *store.Store {
	t.Helper()
	base := os.Getenv(EnvVar)
	if base == "" {
		t.Skipf("%s tanımlı değil; PostgreSQL entegrasyon testi atlandı", EnvVar)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("test veritabanı sunucusuna bağlanılamadı: %v", err)
	}
	defer admin.Close(ctx)

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "ber_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("test veritabanı oluşturulamadı: %v", err)
	}

	u, err := url.Parse(base)
	if err != nil {
		t.Fatalf("%s geçersiz: %v", EnvVar, err)
	}
	u.Path = "/" + name
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		s.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, base)
		if err != nil {
			t.Logf("test veritabanı silinemedi: %v", err)
			return
		}
		defer conn.Close(ctx)
		if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("test veritabanı silinemedi: %v", err)
		}
	})
	return s
}
