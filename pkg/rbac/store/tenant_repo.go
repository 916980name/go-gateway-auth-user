package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantRepo struct {
	pool *pgxpool.Pool
}

func NewTenantRepo(pool *pgxpool.Pool) *TenantRepo {
	return &TenantRepo{pool: pool}
}

func (r *TenantRepo) Create(ctx context.Context, t *Tenant) error {
	return r.pool.QueryRow(ctx,
		`INSERT INTO tenants (code, name, hostname, status)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, uuid, created_at, updated_at`,
		t.Code, t.Name, t.Hostname, int16(1),
	).Scan(&t.ID, &t.UUID, &t.CreatedAt, &t.UpdatedAt)
}

func (r *TenantRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE uuid = $1`, uid,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) List(ctx context.Context, p PaginationParams) (*PaginatedResult[Tenant], error) {
	var total int
	err := r.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE status = 1`).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count tenants: %w", err)
	}
	offset := (p.Page - 1) * p.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE status = 1 ORDER BY id LIMIT $1 OFFSET $2`,
		p.PageSize, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var items []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return &PaginatedResult[Tenant]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: total},
	}, nil
}

func (r *TenantRepo) Update(ctx context.Context, uid uuid.UUID, name, hostname *string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`UPDATE tenants SET
			name = COALESCE($2, name),
			hostname = COALESCE($3, hostname),
			updated_at = $4
		 WHERE uuid = $1
		 RETURNING id, uuid, code, name, hostname, status, created_at, updated_at`,
		uid, name, hostname, time.Now(),
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) SoftDelete(ctx context.Context, uid uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE tenants SET status = 0, updated_at = $2 WHERE uuid = $1`,
		uid, time.Now(),
	)
	return err
}

func (r *TenantRepo) GetByHostname(ctx context.Context, hostname string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE hostname = $1 AND status = 1`, hostname,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE code = $1`, code,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) ListAllActive(ctx context.Context) ([]Tenant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE status = 1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, t)
	}
	return items, nil
}
