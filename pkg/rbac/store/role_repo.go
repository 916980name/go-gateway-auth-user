package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RoleRepo struct {
	pool *pgxpool.Pool
}

func NewRoleRepo(pool *pgxpool.Pool) *RoleRepo {
	return &RoleRepo{pool: pool}
}

func (r *RoleRepo) Create(ctx context.Context, tenantUUID uuid.UUID, role *Role) error {
	var tenantID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	role.TenantID = tenantID
	return r.pool.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, code, name, description)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, uuid, created_at, updated_at`,
		tenantID, role.Code, role.Name, role.Description,
	).Scan(&role.ID, &role.UUID, &role.CreatedAt, &role.UpdatedAt)
}

func (r *RoleRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Role, error) {
	role := &Role{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, tenant_id, code, name, description, created_at, updated_at
		 FROM roles WHERE uuid = $1`, uid,
	).Scan(&role.ID, &role.UUID, &role.TenantID, &role.Code, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Role], error) {
	var tenantID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int
	err = r.pool.QueryRow(ctx, `SELECT count(*) FROM roles WHERE tenant_id = $1`, tenantID).Scan(&total)
	if err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT id, uuid, tenant_id, code, name, description, created_at, updated_at
		 FROM roles WHERE tenant_id = $1 ORDER BY id LIMIT $2 OFFSET $3`,
		tenantID, p.PageSize, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.UUID, &role.TenantID, &role.Code, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, role)
	}
	return &PaginatedResult[Role]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: total},
	}, nil
}

func (r *RoleRepo) Update(ctx context.Context, uid uuid.UUID, name, description *string) (*Role, error) {
	role := &Role{}
	err := r.pool.QueryRow(ctx,
		`UPDATE roles SET
			name = COALESCE($2, name),
			description = COALESCE($3, description),
			updated_at = $4
		 WHERE uuid = $1
		 RETURNING id, uuid, tenant_id, code, name, description, created_at, updated_at`,
		uid, name, description, time.Now(),
	).Scan(&role.ID, &role.UUID, &role.TenantID, &role.Code, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepo) Delete(ctx context.Context, uid uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM roles WHERE uuid = $1`, uid)
	return err
}

func (r *RoleRepo) GetUserRolesInTenant(ctx context.Context, tenantUUID, userUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Role], error) {
	var tenantID, userID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}
	err = r.pool.QueryRow(ctx, `SELECT id FROM users WHERE uuid = $1`, userUUID).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var total int
	err = r.pool.QueryRow(ctx,
		`SELECT count(*) FROM user_roles ur JOIN roles ro ON ur.role_id = ro.id
		 WHERE ur.user_id = $1 AND ur.tenant_id = $2`, userID, tenantID,
	).Scan(&total)
	if err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT ro.id, ro.uuid, ro.tenant_id, ro.code, ro.name, ro.description, ro.created_at, ro.updated_at
		 FROM user_roles ur JOIN roles ro ON ur.role_id = ro.id
		 WHERE ur.user_id = $1 AND ur.tenant_id = $2
		 ORDER BY ro.id LIMIT $3 OFFSET $4`,
		userID, tenantID, p.PageSize, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.UUID, &role.TenantID, &role.Code, &role.Name, &role.Description, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, role)
	}
	return &PaginatedResult[Role]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: total},
	}, nil
}

func (r *RoleRepo) SetUserRoles(ctx context.Context, tenantUUID, userUUID uuid.UUID, roleUUIDs []uuid.UUID) error {
	var tenantID, userID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	err = r.pool.QueryRow(ctx, `SELECT id FROM users WHERE uuid = $1`, userUUID).Scan(&userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2`, userID, tenantID)
	if err != nil {
		return err
	}

	if len(roleUUIDs) > 0 {
		batch := &pgx.Batch{}
		for _, roleUID := range roleUUIDs {
			batch.Queue(
				`INSERT INTO user_roles (user_id, role_id, tenant_id)
				 SELECT $1, id, $2 FROM roles WHERE uuid = $3 AND tenant_id = $2`,
				userID, tenantID, roleUID,
			)
		}
		br := tx.SendBatch(ctx, batch)
		for range roleUUIDs {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return err
			}
		}
		br.Close()
	}

	return tx.Commit(ctx)
}
