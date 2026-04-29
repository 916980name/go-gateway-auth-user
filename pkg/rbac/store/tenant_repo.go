package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type TenantRepo struct {
	db *gorm.DB
}

func NewTenantRepo(db *gorm.DB) *TenantRepo {
	return &TenantRepo{db: db}
}

func (r *TenantRepo) Create(ctx context.Context, t *Tenant) error {
	t.UUID = uuid.New()
	t.Status = 1
	return r.db.WithContext(ctx).Create(t).Error
}

func (r *TenantRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(t).Error; err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) List(ctx context.Context, p PaginationParams) (*PaginatedResult[Tenant], error) {
	var total int64
	if err := r.db.WithContext(ctx).Model(&Tenant{}).Where("status = ?", 1).Count(&total).Error; err != nil {
		return nil, err
	}
	offset := (p.Page - 1) * p.PageSize
	var items []Tenant
	if err := r.db.WithContext(ctx).Where("status = ?", 1).Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[Tenant]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *TenantRepo) Update(ctx context.Context, uid uuid.UUID, name *string) (*Tenant, error) {
	updates := map[string]any{}
	if name != nil {
		updates["name"] = *name
	}
	if len(updates) > 0 {
		updates["updated_at"] = time.Now()
		if err := r.db.WithContext(ctx).Model(&Tenant{}).Where("uuid = ?", uid).Updates(updates).Error; err != nil {
			return nil, err
		}
	}
	t := &Tenant{}
	if err := r.db.WithContext(ctx).Where("uuid = ?", uid).First(t).Error; err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) SoftDelete(ctx context.Context, uid uuid.UUID) error {
	return r.db.WithContext(ctx).Model(&Tenant{}).Where("uuid = ?", uid).
		Updates(map[string]any{"status": int16(0), "updated_at": time.Now()}).Error
}

func (r *TenantRepo) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t := &Tenant{}
	if err := r.db.WithContext(ctx).Where("code = ?", code).First(t).Error; err != nil {
		return nil, err
	}
	return t, nil
}

func (r *TenantRepo) ListAllActive(ctx context.Context) ([]Tenant, error) {
	var items []Tenant
	if err := r.db.WithContext(ctx).Where("status = ?", 1).Order("id").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}
