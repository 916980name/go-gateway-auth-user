package store

import (
	"context"
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const (
	SystemTenantCode = "__system__"
	SystemTenantName = "System"
)

func Seed(ctx context.Context, db *gorm.DB) error {
	return db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		tenant := Tenant{Code: SystemTenantCode, Name: SystemTenantName, Status: 1}
		if err := tx.Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "code"}},
			DoUpdates: clause.AssignmentColumns([]string{"code"}),
		}).Omit("UUID").Create(&tenant).Error; err != nil {
			return fmt.Errorf("upsert system tenant: %w", err)
		}

		return nil
	})
}
