package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	SystemTenantCode    = "__system__"
	SystemTenantName    = "System"
	SystemTenantDomain  = "__system__"
	SystemAdminRoleCode = "system_admin"
	SystemAdminRoleName  = "System Administrator"
	TenantAdminRoleCode  = "tenant_admin"
	TenantAdminRoleName  = "Tenant Administrator"
)

func Seed(ctx context.Context, db *gorm.DB, superAdminUsername string) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenant := Tenant{Code: SystemTenantCode, Name: SystemTenantName, Status: 1}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"code"}),
		}).Omit("UUID").Create(&tenant).Error; err != nil {
			return fmt.Errorf("upsert system tenant: %w", err)
		}

		domain := TenantDomain{TenantID: tenant.ID, Pattern: SystemTenantDomain, IsWildcard: false}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&domain).Error; err != nil {
			return fmt.Errorf("upsert system tenant domain: %w", err)
		}

		role := Role{TenantID: tenant.ID, Code: SystemAdminRoleCode, Name: SystemAdminRoleName, Description: "Full system access across all tenants"}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"code"}),
		}).Omit("UUID").Create(&role).Error; err != nil {
			return fmt.Errorf("upsert system_admin role: %w", err)
		}

		if superAdminUsername == "" {
			return nil
		}

		user := User{Username: superAdminUsername, DisplayName: "Super Admin", Status: 1}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "username"}},
			DoUpdates: clause.AssignmentColumns([]string{"username"}),
		}).Omit("UUID").Create(&user).Error; err != nil {
			return fmt.Errorf("upsert super admin user: %w", err)
		}

		tu := TenantUser{UserID: user.ID, TenantID: tenant.ID, Status: 1}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&tu).Error; err != nil {
			return fmt.Errorf("add super admin to system tenant: %w", err)
		}

		ur := UserRole{UserID: user.ID, RoleID: role.ID, TenantID: tenant.ID}
		if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&ur).Error; err != nil {
			return fmt.Errorf("assign system_admin role: %w", err)
		}

		return nil
	})
}
