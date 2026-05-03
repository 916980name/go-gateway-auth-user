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

func Seed(ctx context.Context, db *gorm.DB) error {
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

		return nil
	})
}
