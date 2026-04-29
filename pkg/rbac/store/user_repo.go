package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserRepo struct {
	db *gorm.DB
}

func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

func (r *UserRepo) Create(ctx context.Context, u *User) error {
	u.UUID = uuid.New()
	u.Status = 1
	return r.db.WithContext(ctx).Create(u).Error
}

func (r *UserRepo) Upsert(ctx context.Context, u *User) error {
	u.Status = 1
	err := r.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "username"}},
			DoUpdates: clause.AssignmentColumns([]string{"username"}),
		}).
		Omit("UUID").
		Create(u).Error
	if err != nil {
		return err
	}
	return r.db.WithContext(ctx).Where("id = ?", u.ID).First(u).Error
}

func (r *UserRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*User, error) {
	u := &User{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) GetByUsername(ctx context.Context, username string) (*User, error) {
	u := &User{}
	if err := r.db.WithContext(ctx).Where("username = ?", username).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) List(ctx context.Context, p PaginationParams, search string) (*PaginatedResult[User], error) {
	countQuery := r.db.WithContext(ctx).Model(&User{}).Where("status = ?", 1)
	if search != "" {
		pattern := "%" + search + "%"
		countQuery = countQuery.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", pattern, pattern, pattern)
	}

	var total int64
	if err := countQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	dataQuery := r.db.WithContext(ctx).Where("status = ?", 1)
	if search != "" {
		pattern := "%" + search + "%"
		dataQuery = dataQuery.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", pattern, pattern, pattern)
	}
	var items []User
	if err := dataQuery.Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[User]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *UserRepo) Update(ctx context.Context, uid uuid.UUID, displayName, email, phone *string) (*User, error) {
	updates := map[string]any{}
	if displayName != nil {
		updates["display_name"] = *displayName
	}
	if email != nil {
		updates["email"] = *email
	}
	if phone != nil {
		updates["phone"] = *phone
	}
	if len(updates) > 0 {
		updates["updated_at"] = time.Now()
		if err := r.db.WithContext(ctx).Model(&User{}).Where("uuid = ?", uid).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	u := &User{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) SoftDelete(ctx context.Context, uid uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&User{}).Where("uuid = ?", uid).
		Updates(map[string]any{"status": int16(0), "updated_at": time.Now()}).Error
}

func (r *UserRepo) ListTenants(ctx context.Context, userUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Tenant], error) {
	var user User
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&user).Error; err != nil {
		return nil, err
	}

	baseQuery := r.db.WithContext(ctx).Model(&Tenant{}).
		Joins("JOIN tenant_users ON tenant_users.tenant_id = tenants.id").
		Where("tenant_users.user_id = ? AND tenant_users.status = 1 AND tenants.status = 1", user.ID)

	var total int64
	if err := baseQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []Tenant
	if err := r.db.WithContext(ctx).
		Joins("JOIN tenant_users ON tenant_users.tenant_id = tenants.id").
		Where("tenant_users.user_id = ? AND tenant_users.status = 1 AND tenants.status = 1", user.ID).
		Order("tenants.id").Limit(p.PageSize).Offset(offset).
		Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[Tenant]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *UserRepo) AddToTenant(ctx context.Context, userUUID, tenantUUID uuid.UUID) error {
	var user User
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&user).Error; err != nil {
		return err
	}
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return err
	}
	tu := TenantUser{UserID: user.ID, TenantID: tenant.ID, Status: 1}
	return r.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "tenant_id"}},
		DoUpdates: clause.AssignmentColumns([]string{"status"}),
	}).Create(&tu).Error
}

func (r *UserRepo) RemoveFromTenant(ctx context.Context, userUUID, tenantUUID uuid.UUID) error {
	var user User
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&user).Error; err != nil {
		return err
	}
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return err
	}
	return r.db.WithContext(ctx).Where("user_id = ? AND tenant_id = ?", user.ID, tenant.ID).Delete(&TenantUser{}).Error
}
