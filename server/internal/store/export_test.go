package store

import (
	"context"

	"github.com/jackc/pgx/v5/pgconn"
)

// ExecForTest, testlerin ham SQL çalıştırmasını sağlar (yalnızca test derlemelerinde vardır).
func (s *Store) ExecForTest(ctx context.Context, sql string) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, sql)
}
