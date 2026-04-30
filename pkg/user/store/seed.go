package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	SystemTenantCode   = "__system__"
	SystemTenantName   = "System"
	SystemTenantDomain = "__system__"
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

		if superAdminUsername == "" {
			return nil
		}

		user := User{TenantID: tenant.ID, Username: superAdminUsername, DisplayName: "Super Admin", Status: 1}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "username"}},
			DoUpdates: clause.AssignmentColumns([]string{"username"}),
		}).Omit("UUID").Create(&user).Error; err != nil {
			return fmt.Errorf("upsert super admin user: %w", err)
		}

		return nil
	})
}
