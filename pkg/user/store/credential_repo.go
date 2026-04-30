package store

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type CredentialRepo struct {
	db *gorm.DB
}

func NewCredentialRepo(db *gorm.DB) *CredentialRepo {
	return &CredentialRepo{db: db}
}

func (r *CredentialRepo) Create(ctx context.Context, c *UserCredential) error {
	c.Status = 1
	return r.db.WithContext(ctx).Create(c).Error
}

func (r *CredentialRepo) GetByUserAndProvider(ctx context.Context, userID, tenantID int64, providerType string) (*UserCredential, error) {
	c := &UserCredential{}
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id = ? AND provider_type = ? AND status = 1", userID, tenantID, providerType).
		First(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

func (r *CredentialRepo) GetByIdentifier(ctx context.Context, tenantID int64, providerType, identifier string) (*UserCredential, error) {
	c := &UserCredential{}
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND provider_type = ? AND identifier = ? AND status = 1", tenantID, providerType, identifier).
		First(c).Error; err != nil {
		return nil, err
	}
	return c, nil
}

func (r *CredentialRepo) ListByUser(ctx context.Context, userID, tenantID int64) ([]UserCredential, error) {
	var items []UserCredential
	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND tenant_id = ? AND status = 1", userID, tenantID).
		Order("id").
		Find(&items).Error; err != nil {
		return nil, err
	}
	return items, nil
}

func (r *CredentialRepo) UpdateCredential(ctx context.Context, id int64, credential string) error {
	return r.db.WithContext(ctx).Model(&UserCredential{}).Where("id = ?", id).
		Updates(map[string]any{"credential": credential, "updated_at": time.Now()}).Error
}

func (r *CredentialRepo) SoftDelete(ctx context.Context, id int64) error {
	return r.db.WithContext(ctx).Model(&UserCredential{}).Where("id = ?", id).
		Updates(map[string]any{"status": int16(0), "updated_at": time.Now()}).Error
}

func (r *CredentialRepo) SoftDeleteByUser(ctx context.Context, id, userID int64) error {
	res := r.db.WithContext(ctx).Model(&UserCredential{}).
		Where("id = ? AND user_id = ?", id, userID).
		Updates(map[string]any{"status": int16(0), "updated_at": time.Now()})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}
