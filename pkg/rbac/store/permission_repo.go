package store

import (
	"context"
	"fmt"
	"time"

	"api-gateway/pkg/common"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PermissionRepo struct {
	db *gorm.DB
}

func NewPermissionRepo(db *gorm.DB) *PermissionRepo {
	return &PermissionRepo{db: db}
}

func (r *PermissionRepo) Create(ctx context.Context, tenantUUID uuid.UUID, p *Permission) error {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	p.TenantID = t.ID
	p.UUID = uuid.New()
	return r.db.WithContext(ctx).Create(p).Error
}

func (r *PermissionRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Permission, error) {
	p := &Permission{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(p).Error; err != nil {
		return nil, err
	}
	return p, nil
}

func (r *PermissionRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, pg common.PaginationParams) (*common.PaginatedResult[Permission], error) {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Permission{}).Where("tenant_id = ?", t.ID).Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (pg.Page - 1) * pg.PageSize
	var items []Permission
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", t.ID).Order("id").Limit(pg.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &common.PaginatedResult[Permission]{
		Data:       items,
		Pagination: common.Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: int(total)},
	}, nil
}

func (r *PermissionRepo) Update(ctx context.Context, uid uuid.UUID, name, resource, action, description *string) (*Permission, error) {
	updates := map[string]any{}
	if name != nil {
		updates["name"] = *name
	}
	if resource != nil {
		updates["resource"] = *resource
	}
	if action != nil {
		updates["action"] = *action
	}
	if description != nil {
		updates["description"] = *description
	}
	if len(updates) > 0 {
		updates["updated_at"] = time.Now()
		if err := r.db.WithContext(ctx).Model(&Permission{}).Where("uuid = ?", uid).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	p := &Permission{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(p).Error; err != nil {
		return nil, err
	}
	return p, nil
}

func (r *PermissionRepo) Delete(ctx context.Context, uid uuid.UUID) error {
	return r.db.WithContext(ctx).Where("uuid = ?", uid).Delete(&Permission{}).Error
}

func (r *PermissionRepo) GetRolePermissions(ctx context.Context, roleUUID uuid.UUID, pg common.PaginationParams) (*common.PaginatedResult[Permission], error) {
	var role Role
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", roleUUID).First(&role).Error; err != nil {
		return nil, fmt.Errorf("role not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Permission{}).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", role.ID).
		Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (pg.Page - 1) * pg.PageSize
	var items []Permission
	if err := r.db.WithContext(ctx).
		Joins("JOIN role_permissions ON role_permissions.permission_id = permissions.id").
		Where("role_permissions.role_id = ?", role.ID).
		Order("permissions.id").Limit(pg.PageSize).Offset(offset).
		Find(&items).Error; err != nil {
		return nil, err
	}
	return &common.PaginatedResult[Permission]{
		Data:       items,
		Pagination: common.Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: int(total)},
	}, nil
}

func (r *PermissionRepo) SetRolePermissions(ctx context.Context, roleUUID uuid.UUID, permissionUUIDs []uuid.UUID) error {
	var role Role
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", roleUUID).First(&role).Error; err != nil {
		return fmt.Errorf("role not found: %w", err)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("role_id = ?", role.ID).Delete(&RolePermission{}).Error; err != nil {
			return err
		}
		for _, permUID := range permissionUUIDs {
			var perm Permission
			if err := tx.Select("id").Where("uuid = ?", permUID).First(&perm).Error; err != nil {
				return err
			}
			rp := RolePermission{RoleID: role.ID, PermissionID: perm.ID}
			if err := tx.Create(&rp).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
