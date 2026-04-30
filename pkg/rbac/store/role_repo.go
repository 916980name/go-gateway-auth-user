package store

import (
	"context"
	"fmt"
	"time"

	"api-gateway/pkg/common"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RoleRepo struct {
	db *gorm.DB
}

func NewRoleRepo(db *gorm.DB) *RoleRepo {
	return &RoleRepo{db: db}
}

func (r *RoleRepo) Create(ctx context.Context, tenantUUID uuid.UUID, role *Role) error {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	role.TenantID = t.ID
	role.UUID = uuid.New()
	return r.db.WithContext(ctx).Create(role).Error
}

func (r *RoleRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Role, error) {
	role := &Role{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(role).Error; err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, p common.PaginationParams) (*common.PaginatedResult[Role], error) {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Role{}).Where("tenant_id = ?", t.ID).Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []Role
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", t.ID).Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &common.PaginatedResult[Role]{
		Data:       items,
		Pagination: common.Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *RoleRepo) Update(ctx context.Context, uid uuid.UUID, name, description *string) (*Role, error) {
	updates := map[string]any{}
	if name != nil {
		updates["name"] = *name
	}
	if description != nil {
		updates["description"] = *description
	}
	if len(updates) > 0 {
		updates["updated_at"] = time.Now()
		if err := r.db.WithContext(ctx).Model(&Role{}).Where("uuid = ?", uid).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	role := &Role{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(role).Error; err != nil {
		return nil, err
	}
	return role, nil
}

func (r *RoleRepo) Delete(ctx context.Context, uid uuid.UUID) error {
	return r.db.WithContext(ctx).Where("uuid = ?", uid).Delete(&Role{}).Error
}

func (r *RoleRepo) GetUserRolesInTenant(ctx context.Context, tenantUUID, userUUID uuid.UUID, p common.PaginationParams) (*common.PaginatedResult[Role], error) {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}
	var u userRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&u).Error; err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Role{}).
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND user_roles.tenant_id = ?", u.ID, t.ID).
		Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []Role
	if err := r.db.WithContext(ctx).
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND user_roles.tenant_id = ?", u.ID, t.ID).
		Order("roles.id").Limit(p.PageSize).Offset(offset).
		Find(&items).Error; err != nil {
		return nil, err
	}
	return &common.PaginatedResult[Role]{
		Data:       items,
		Pagination: common.Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *RoleRepo) SetUserRoles(ctx context.Context, tenantUUID, userUUID uuid.UUID, roleUUIDs []uuid.UUID) error {
	var t tenantRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&t).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	var u userRef
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&u).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ? AND tenant_id = ?", u.ID, t.ID).Delete(&UserRole{}).Error; err != nil {
			return err
		}
		for _, roleUID := range roleUUIDs {
			var role Role
			if err := tx.Select("id").Where("uuid = ? AND tenant_id = ?", roleUID, t.ID).First(&role).Error; err != nil {
				return err
			}
			ur := UserRole{UserID: u.ID, RoleID: role.ID, TenantID: t.ID}
			if err := tx.Create(&ur).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
