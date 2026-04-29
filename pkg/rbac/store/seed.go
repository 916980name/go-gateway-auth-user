package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	SystemTenantCode     = "__system__"
	SystemTenantName     = "System"
	SystemTenantHostname = "__system__"
	SystemAdminRoleCode  = "system_admin"
	SystemAdminRoleName  = "System Administrator"
	TenantAdminRoleCode  = "tenant_admin"
	TenantAdminRoleName  = "Tenant Administrator"
)

func Seed(ctx context.Context, pool *pgxpool.Pool, superAdminUsername string) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	var tenantID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO tenants (code, name, hostname, status)
		 VALUES ($1, $2, $3, 1)
		 ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
		 RETURNING id`,
		SystemTenantCode, SystemTenantName, SystemTenantHostname,
	).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("upsert system tenant: %w", err)
	}

	var roleID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, code, name, description)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, code) DO UPDATE SET code = EXCLUDED.code
		 RETURNING id`,
		tenantID, SystemAdminRoleCode, SystemAdminRoleName, "Full system access across all tenants",
	).Scan(&roleID)
	if err != nil {
		return fmt.Errorf("upsert system_admin role: %w", err)
	}

	if superAdminUsername == "" {
		return tx.Commit(ctx)
	}

	var userID int64
	err = tx.QueryRow(ctx,
		`INSERT INTO users (username, display_name, status)
		 VALUES ($1, $2, 1)
		 ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
		 RETURNING id`,
		superAdminUsername, "Super Admin",
	).Scan(&userID)
	if err != nil {
		return fmt.Errorf("upsert super admin user: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO tenant_users (user_id, tenant_id, status)
		 VALUES ($1, $2, 1)
		 ON CONFLICT (user_id, tenant_id) DO NOTHING`,
		userID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("add super admin to system tenant: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, tenant_id)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (user_id, role_id, tenant_id) DO NOTHING`,
		userID, roleID, tenantID,
	)
	if err != nil {
		return fmt.Errorf("assign system_admin role: %w", err)
	}

	return tx.Commit(ctx)
}
