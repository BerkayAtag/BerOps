// Package store, sunucunun PostgreSQL erişim katmanıdır.
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.up.sql
var migrationFS embed.FS

// migrationLockID, eşzamanlı başlayan sunucuların migration'ı aynı anda çalıştırmasını önler.
const migrationLockID = 0x42455201 // "BER" + 1

// ErrNotFound, kayıt bulunamadığında döner.
var ErrNotFound = errors.New("kayıt bulunamadı")

// ErrConflict, benzersizlik kısıtı ihlal edildiğinde döner.
var ErrConflict = errors.New("kayıt zaten var")

// Store, veritabanı bağlantı havuzunu sarar.
type Store struct {
	pool *pgxpool.Pool
}

// Open, veritabanına bağlanır ve bağlantıyı doğrular.
func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("veritabanı adresi geçersiz: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("veritabanına bağlanılamadı: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("veritabanına bağlanılamadı: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close, bağlantı havuzunu kapatır.
func (s *Store) Close() { s.pool.Close() }

// Ping, veritabanı erişimini denetler (sağlık kontrolü için).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, e := range entries {
		name := e.Name()
		num, _, ok := strings.Cut(name, "_")
		if !ok {
			return nil, fmt.Errorf("migration adı geçersiz: %s", name)
		}
		v, err := strconv.Atoi(num)
		if err != nil {
			return nil, fmt.Errorf("migration numarası geçersiz: %s", name)
		}
		body, err := fs.ReadFile(migrationFS, "migrations/"+name)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("aynı numaralı iki migration: %s, %s", out[i-1].name, out[i].name)
		}
	}
	return out, nil
}

// Migrate, uygulanmamış migration'ları sırayla, her birini ayrı transaction içinde uygular.
// Uygulanan sürümlerin listesini döner.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockID); err != nil {
		return nil, fmt.Errorf("migration kilidi alınamadı: %w", err)
	}
	defer conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockID) //nolint:errcheck

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    integer PRIMARY KEY,
		name       text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return nil, err
	}

	applied := map[int]bool{}
	rows, err := conn.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var done []string
	for _, m := range migs {
		if applied[m.version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name)
			return err
		})
		if err != nil {
			return done, fmt.Errorf("migration %s uygulanamadı: %w", m.name, err)
		}
		done = append(done, m.name)
	}
	return done, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
