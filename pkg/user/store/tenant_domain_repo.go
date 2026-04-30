package store

import (
	"context"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

type TenantDomainRepo struct {
	db *gorm.DB
}

func NewTenantDomainRepo(db *gorm.DB) *TenantDomainRepo {
	return &TenantDomainRepo{db: db}
}

type DomainWithTenant struct {
	Pattern    string
	TenantCode string
	IsWildcard bool
}

func (r *TenantDomainRepo) Create(ctx context.Context, d *TenantDomain) error {
	d.IsWildcard = strings.HasPrefix(d.Pattern, "*.")
	return r.db.WithContext(ctx).Create(d).Error
}

func (r *TenantDomainRepo) Delete(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Delete(&TenantDomain{}, id).Error
}

func (r *TenantDomainRepo) ListByTenant(ctx context.Context, tenantID int64) ([]TenantDomain, error) {
	var items []TenantDomain
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenantID).Order("id").Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (r *TenantDomainRepo) ListAllWithTenant(ctx context.Context) ([]DomainWithTenant, error) {
	var items []DomainWithTenant
	err := r.db.WithContext(ctx).
		Model(&TenantDomain{}).
		Select("tenant_domains.pattern, tenants.code as tenant_code, tenant_domains.is_wildcard").
		Joins("JOIN tenants ON tenants.id = tenant_domains.tenant_id").
		Where("tenants.status = ?", 1).
		Order("tenant_domains.id").
		Scan(&items).Error
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (r *TenantDomainRepo) CheckOverlap(ctx context.Context, tenantID int64, pattern string) error {
	isWildcard := strings.HasPrefix(pattern, "*.")

	if isWildcard {
		suffix := strings.TrimPrefix(pattern, "*.")
		likePattern := "%." + suffix
		var count int64
		err := r.db.WithContext(ctx).Model(&TenantDomain{}).
			Where("tenant_id != ? AND is_wildcard = false AND (pattern LIKE ? OR pattern = ?)", tenantID, likePattern, suffix).
			Count(&count).Error
		if err != nil {
			return fmt.Errorf("check overlap: %w", err)
		}
		if count > 0 {
			return fmt.Errorf("wildcard %s overlaps with %d existing exact domain(s) from other tenants", pattern, count)
		}
	} else {
		parts := strings.SplitN(pattern, ".", 2)
		if len(parts) == 2 {
			wildcardPattern := "*." + parts[1]
			var count int64
			err := r.db.WithContext(ctx).Model(&TenantDomain{}).
				Where("tenant_id != ? AND pattern = ?", tenantID, wildcardPattern).
				Count(&count).Error
			if err != nil {
				return fmt.Errorf("check overlap: %w", err)
			}
			if count > 0 {
				return fmt.Errorf("exact domain %s overlaps with wildcard %s from another tenant", pattern, wildcardPattern)
			}
		}
	}
	return nil
}

func (r *TenantDomainRepo) GetByID(ctx context.Context, id int64) (*TenantDomain, error) {
	d := &TenantDomain{}
	if err := r.db.WithContext(ctx).First(d, id).Error; err != nil {
		return nil, err
	}
	return d, nil
}
