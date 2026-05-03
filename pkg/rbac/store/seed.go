package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	SystemTenantCode    = "__system__"
	SystemAdminRoleCode = "system_admin"
	SystemAdminRoleName = "System Administrator"
	TenantAdminRoleCode = "tenant_admin"
	TenantAdminRoleName = "Tenant Administrator"
)

func Seed(ctx context.Context, db *gorm.DB, adminPath string) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tenant tenantRef
		if err := tx.Where("code = ?", SystemTenantCode).First(&tenant).Error; err != nil {
			return fmt.Errorf("system tenant not found (user seed must run first): %w", err)
		}

		role := Role{TenantID: tenant.ID, Code: SystemAdminRoleCode, Name: SystemAdminRoleName, Description: "Full system access across all tenants"}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"code"}),
		}).Omit("UUID").Create(&role).Error; err != nil {
			return fmt.Errorf("upsert system_admin role: %w", err)
		}

		taRole := Role{TenantID: tenant.ID, Code: TenantAdminRoleCode, Name: TenantAdminRoleName, Description: "Full access within a single tenant"}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"code"}),
		}).Omit("UUID").Create(&taRole).Error; err != nil {
			return fmt.Errorf("upsert tenant_admin role: %w", err)
		}

		// Seed system admin policies for admin route access
		systemAdminPolicies := [][]interface{}{
			{"p", SystemAdminRoleCode, SystemTenantCode, adminPath + "/tenants", "*"},
			{"p", SystemAdminRoleCode, SystemTenantCode, adminPath + "/tenants/*", "*"},
			{"p", SystemAdminRoleCode, SystemTenantCode, adminPath + "/tenants/*/domains", "*"},
			{"p", SystemAdminRoleCode, SystemTenantCode, adminPath + "/tenants/*/domains/*", "*"},
			{"p", SystemAdminRoleCode, SystemTenantCode, adminPath + "/tenants/*/admins", "*"},
		}
		for _, p := range systemAdminPolicies {
			if err := tx.Exec(
				`INSERT INTO casbin_rules (ptype, v0, v1, v2, v3) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
				p...,
			).Error; err != nil {
				return fmt.Errorf("insert system admin casbin policy: %w", err)
			}
		}

		return nil
	})
}

// SeedTenantAdminPolicies inserts Casbin policies for tenant_admin role in the given tenant.
// Should be called within a transaction after the tenant is created.
func SeedTenantAdminPolicies(tx *gorm.DB, tenantCode string, adminPath string) error {
	policies := [][]interface{}{
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/users", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/users/*", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/users/*/credentials", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/users/*/credentials/*", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/roles", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/roles/*", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/roles/*/permissions", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/permissions", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/permissions/*", "*"},
		{"p", TenantAdminRoleCode, tenantCode, adminPath + "/users/*/roles", "*"},
	}
	for _, p := range policies {
		if err := tx.Exec(
			`INSERT INTO casbin_rules (ptype, v0, v1, v2, v3) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			p...,
		).Error; err != nil {
			return fmt.Errorf("insert tenant admin casbin policy: %w", err)
		}
	}
	return nil
}
