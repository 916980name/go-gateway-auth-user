package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func (r *UserRepo) Create(ctx context.Context, u *User) error {
	return r.pool.QueryRow(ctx,
		`INSERT INTO users (username, display_name, email, phone, status)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, uuid, created_at, updated_at`,
		u.Username, u.DisplayName, u.Email, u.Phone, int16(1),
	).Scan(&u.ID, &u.UUID, &u.CreatedAt, &u.UpdatedAt)
}

func (r *UserRepo) Upsert(ctx context.Context, u *User) error {
	return r.pool.QueryRow(ctx,
		`INSERT INTO users (username, display_name, email, phone, status)
		 VALUES ($1, $2, $3, $4, 1)
		 ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
		 RETURNING id, uuid, status, created_at, updated_at`,
		u.Username, u.DisplayName, u.Email, u.Phone,
	).Scan(&u.ID, &u.UUID, &u.Status, &u.CreatedAt, &u.UpdatedAt)
}

func (r *UserRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, username, display_name, email, phone, status, created_at, updated_at
		 FROM users WHERE uuid = $1`, uid,
	).Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.Phone, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, username, display_name, email, phone, status, created_at, updated_at
		 FROM users WHERE username = $1`, username,
	).Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.Phone, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) List(ctx context.Context, p PaginationParams, search string) (*PaginatedResult[User], error) {
	var total int
	var countQuery string
	var args []any

	if search != "" {
		countQuery = `SELECT count(*) FROM users WHERE status = 1 AND (username ILIKE $1 OR display_name ILIKE $1 OR email ILIKE $1)`
		args = append(args, "%"+search+"%")
	} else {
		countQuery = `SELECT count(*) FROM users WHERE status = 1`
	}
	err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return nil, fmt.Errorf("count users: %w", err)
	}

	offset := (p.Page - 1) * p.PageSize
	var dataQuery string
	var dataArgs []any

	if search != "" {
		dataQuery = `SELECT id, uuid, username, display_name, email, phone, status, created_at, updated_at
		 FROM users WHERE status = 1 AND (username ILIKE $1 OR display_name ILIKE $1 OR email ILIKE $1)
		 ORDER BY id LIMIT $2 OFFSET $3`
		dataArgs = []any{"%" + search + "%", p.PageSize, offset}
	} else {
		dataQuery = `SELECT id, uuid, username, display_name, email, phone, status, created_at, updated_at
		 FROM users WHERE status = 1 ORDER BY id LIMIT $1 OFFSET $2`
		dataArgs = []any{p.PageSize, offset}
	}
	rows, err := r.pool.Query(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var items []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.Phone, &u.Status, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, u)
	}
	return &PaginatedResult[User]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: total},
	}, nil
}

func (r *UserRepo) Update(ctx context.Context, uid uuid.UUID, displayName, email, phone *string) (*User, error) {
	u := &User{}
	err := r.pool.QueryRow(ctx,
		`UPDATE users SET
			display_name = COALESCE($2, display_name),
			email = COALESCE($3, email),
			phone = COALESCE($4, phone),
			updated_at = $5
		 WHERE uuid = $1
		 RETURNING id, uuid, username, display_name, email, phone, status, created_at, updated_at`,
		uid, displayName, email, phone, time.Now(),
	).Scan(&u.ID, &u.UUID, &u.Username, &u.DisplayName, &u.Email, &u.Phone, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) SoftDelete(ctx context.Context, uid uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE users SET status = 0, updated_at = $2 WHERE uuid = $1`,
		uid, time.Now(),
	)
	return err
}

func (r *UserRepo) ListTenants(ctx context.Context, userUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Tenant], error) {
	var userID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM users WHERE uuid = $1`, userUUID).Scan(&userID)
	if err != nil {
		return nil, err
	}

	var total int
	err = r.pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_users tu JOIN tenants t ON tu.tenant_id = t.id
		 WHERE tu.user_id = $1 AND tu.status = 1 AND t.status = 1`, userID,
	).Scan(&total)
	if err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT t.id, t.uuid, t.code, t.name, t.hostname, t.status, t.created_at, t.updated_at
		 FROM tenant_users tu JOIN tenants t ON tu.tenant_id = t.id
		 WHERE tu.user_id = $1 AND tu.status = 1 AND t.status = 1
		 ORDER BY t.id LIMIT $2 OFFSET $3`,
		userID, p.PageSize, offset,
	)
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
	return &PaginatedResult[Tenant]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: total},
	}, nil
}

func (r *UserRepo) AddToTenant(ctx context.Context, userUUID, tenantUUID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO tenant_users (user_id, tenant_id, status)
		 SELECT u.id, t.id, 1
		 FROM users u, tenants t
		 WHERE u.uuid = $1 AND t.uuid = $2
		 ON CONFLICT (user_id, tenant_id) DO UPDATE SET status = 1`,
		userUUID, tenantUUID,
	)
	return err
}

func (r *UserRepo) RemoveFromTenant(ctx context.Context, userUUID, tenantUUID uuid.UUID) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM tenant_users
		 WHERE user_id = (SELECT id FROM users WHERE uuid = $1)
		   AND tenant_id = (SELECT id FROM tenants WHERE uuid = $2)`,
		userUUID, tenantUUID,
	)
	return err
}
