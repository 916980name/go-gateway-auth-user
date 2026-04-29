package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PermissionRepo struct {
	pool *pgxpool.Pool
}

func NewPermissionRepo(pool *pgxpool.Pool) *PermissionRepo {
	return &PermissionRepo{pool: pool}
}

func (r *PermissionRepo) Create(ctx context.Context, tenantUUID uuid.UUID, p *Permission) error {
	var tenantID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	p.TenantID = tenantID
	return r.pool.QueryRow(ctx,
		`INSERT INTO permissions (tenant_id, code, name, resource, action, description)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, uuid, created_at, updated_at`,
		tenantID, p.Code, p.Name, p.Resource, p.Action, p.Description,
	).Scan(&p.ID, &p.UUID, &p.CreatedAt, &p.UpdatedAt)
}

func (r *PermissionRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Permission, error) {
	p := &Permission{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, tenant_id, code, name, resource, action, description, created_at, updated_at
		 FROM permissions WHERE uuid = $1`, uid,
	).Scan(&p.ID, &p.UUID, &p.TenantID, &p.Code, &p.Name, &p.Resource, &p.Action, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *PermissionRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, pg PaginationParams) (*PaginatedResult[Permission], error) {
	var tenantID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM tenants WHERE uuid = $1`, tenantUUID).Scan(&tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int
	err = r.pool.QueryRow(ctx, `SELECT count(*) FROM permissions WHERE tenant_id = $1`, tenantID).Scan(&total)
	if err != nil {
		return nil, err
	}

	offset := (pg.Page - 1) * pg.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT id, uuid, tenant_id, code, name, resource, action, description, created_at, updated_at
		 FROM permissions WHERE tenant_id = $1 ORDER BY id LIMIT $2 OFFSET $3`,
		tenantID, pg.PageSize, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.UUID, &p.TenantID, &p.Code, &p.Name, &p.Resource, &p.Action, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return &PaginatedResult[Permission]{
		Data:       items,
		Pagination: Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: total},
	}, nil
}

func (r *PermissionRepo) Update(ctx context.Context, uid uuid.UUID, name, resource, action, description *string) (*Permission, error) {
	p := &Permission{}
	err := r.pool.QueryRow(ctx,
		`UPDATE permissions SET
			name = COALESCE($2, name),
			resource = COALESCE($3, resource),
			action = COALESCE($4, action),
			description = COALESCE($5, description),
			updated_at = $6
		 WHERE uuid = $1
		 RETURNING id, uuid, tenant_id, code, name, resource, action, description, created_at, updated_at`,
		uid, name, resource, action, description, time.Now(),
	).Scan(&p.ID, &p.UUID, &p.TenantID, &p.Code, &p.Name, &p.Resource, &p.Action, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *PermissionRepo) Delete(ctx context.Context, uid uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM permissions WHERE uuid = $1`, uid)
	return err
}

func (r *PermissionRepo) GetRolePermissions(ctx context.Context, roleUUID uuid.UUID, pg PaginationParams) (*PaginatedResult[Permission], error) {
	var roleID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM roles WHERE uuid = $1`, roleUUID).Scan(&roleID)
	if err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	var total int
	err = r.pool.QueryRow(ctx,
		`SELECT count(*) FROM role_permissions WHERE role_id = $1`, roleID,
	).Scan(&total)
	if err != nil {
		return nil, err
	}

	offset := (pg.Page - 1) * pg.PageSize
	rows, err := r.pool.Query(ctx,
		`SELECT p.id, p.uuid, p.tenant_id, p.code, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
		 FROM role_permissions rp JOIN permissions p ON rp.permission_id = p.id
		 WHERE rp.role_id = $1
		 ORDER BY p.id LIMIT $2 OFFSET $3`,
		roleID, pg.PageSize, offset,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.UUID, &p.TenantID, &p.Code, &p.Name, &p.Resource, &p.Action, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return &PaginatedResult[Permission]{
		Data:       items,
		Pagination: Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: total},
	}, nil
}

func (r *PermissionRepo) SetRolePermissions(ctx context.Context, roleUUID uuid.UUID, permissionUUIDs []uuid.UUID) error {
	var roleID int64
	err := r.pool.QueryRow(ctx, `SELECT id FROM roles WHERE uuid = $1`, roleUUID).Scan(&roleID)
	if err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID)
	if err != nil {
		return err
	}

	if len(permissionUUIDs) > 0 {
		batch := &pgx.Batch{}
		for _, permUID := range permissionUUIDs {
			batch.Queue(
				`INSERT INTO role_permissions (role_id, permission_id)
				 SELECT $1, id FROM permissions WHERE uuid = $2`,
				roleID, permUID,
			)
		}
		br := tx.SendBatch(ctx, batch)
		for range permissionUUIDs {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return err
			}
		}
		br.Close()
	}

	return tx.Commit(ctx)
}
