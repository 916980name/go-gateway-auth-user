package store

import (
	"context"
	"strings"
	"time"
	"unicode"

	"api-gateway/pkg/common"

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
			Columns:   []clause.Column{{Name: "tenant_id"}, {Name: "username"}},
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

func (r *UserRepo) GetByUsername(ctx context.Context, tenantID int64, username string) (*User, error) {
	u := &User{}
	if err := r.db.WithContext(ctx).Where("tenant_id = ? AND username = ?", tenantID, username).First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func (r *UserRepo) FindByIdentifier(ctx context.Context, tenantID int64, identifier string) (*User, error) {
	u := &User{}
	col := inferIdentifierColumn(identifier)
	if err := r.db.WithContext(ctx).
		Where("tenant_id = ? AND "+col+" = ? AND status = 1", tenantID, identifier).
		First(u).Error; err != nil {
		return nil, err
	}
	return u, nil
}

func inferIdentifierColumn(identifier string) string {
	if strings.Contains(identifier, "@") {
		return "email"
	}
	if strings.HasPrefix(identifier, "+") || isAllDigits(identifier) {
		return "phone"
	}
	return "username"
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `%`, `\%`)
	s = strings.ReplaceAll(s, `_`, `\_`)
	return s
}

func (r *UserRepo) List(ctx context.Context, tenantID int64, p common.PaginationParams, search string) (*common.PaginatedResult[User], error) {
	countQuery := r.db.WithContext(ctx).Model(&User{}).Where("tenant_id = ? AND status = ?", tenantID, 1)
	if search != "" {
		pattern := "%" + escapeLike(search) + "%"
		countQuery = countQuery.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", pattern, pattern, pattern)
	}

	var total int64
	if err := countQuery.Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	dataQuery := r.db.WithContext(ctx).Where("tenant_id = ? AND status = ?", tenantID, 1)
	if search != "" {
		pattern := "%" + escapeLike(search) + "%"
		dataQuery = dataQuery.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", pattern, pattern, pattern)
	}
	var items []User
	if err := dataQuery.Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &common.PaginatedResult[User]{
		Data:       items,
		Pagination: common.Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
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
