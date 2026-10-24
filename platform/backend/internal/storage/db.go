package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool *pgxpool.Pool
}

func Connect(ctx context.Context, url string) (*DB, error) {
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{Pool: pool}, nil
}

func (d *DB) Close() {
	d.Pool.Close()
}

func (d *DB) Migrate(ctx context.Context, sql string) error {
	_, err := d.Pool.Exec(ctx, sql)
	if err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}
