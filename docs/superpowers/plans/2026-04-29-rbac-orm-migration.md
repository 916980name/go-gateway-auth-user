# RBAC ORM Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace all raw SQL (pgx/v5) in the RBAC data access layer with GORM, so struct field changes no longer require updating every related SQL statement.

**Architecture:** Add gorm struct tags to existing models, replace the pgxpool connection with `*gorm.DB`, rewrite each repository method using GORM's query API, and update the initialization chain. Schema migrations stay on golang-migrate; Casbin is untouched.

**Tech Stack:** Go, GORM v2, gorm.io/driver/postgres, PostgreSQL

---

## File Structure

| File | Action | Responsibility |
|------|--------|----------------|
| `pkg/rbac/store/models.go` | Modify | Add gorm struct tags to all 8 model structs |
| `pkg/rbac/store/db.go` | Rewrite | Replace `NewPool() *pgxpool.Pool` with `NewDB() *gorm.DB` |
| `pkg/rbac/store/tenant_repo.go` | Rewrite | 7 methods: Create, GetByUUID, GetByCode, List, Update, SoftDelete, ListAllActive |
| `pkg/rbac/store/tenant_domain_repo.go` | Rewrite | 6 methods: Create, Delete, ListByTenant, ListAllWithTenant, CheckOverlap, GetByID |
| `pkg/rbac/store/user_repo.go` | Rewrite | 10 methods: Create, Upsert, GetByUUID, GetByUsername, List, Update, SoftDelete, ListTenants, AddToTenant, RemoveFromTenant |
| `pkg/rbac/store/role_repo.go` | Rewrite | 7 methods: Create, GetByUUID, ListByTenant, Update, Delete, GetUserRolesInTenant, SetUserRoles |
| `pkg/rbac/store/permission_repo.go` | Rewrite | 7 methods: Create, GetByUUID, ListByTenant, Update, Delete, GetRolePermissions, SetRolePermissions |
| `pkg/rbac/store/seed.go` | Rewrite | Replace pgxpool transaction with GORM transaction |
| `pkg/rbac/rbac.go` | Modify | Update initialization: NewPool→NewDB, repo constructors take `*gorm.DB` |
| `go.mod` | Modify | Add gorm.io/gorm, gorm.io/driver/postgres |

---

### Task 1: Add GORM dependencies

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Install GORM and PostgreSQL driver**

Run:
```bash
go get gorm.io/gorm gorm.io/driver/postgres
```

- [ ] **Step 2: Tidy modules**

Run:
```bash
go mod tidy
```

---

### Task 2: Update models with gorm struct tags

**Files:**
- Modify: `pkg/rbac/store/models.go`

- [ ] **Step 1: Replace the entire models.go content**

Replace the full content of `pkg/rbac/store/models.go` with:

```go
package store

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          int64     `json:"-" gorm:"primaryKey"`
	UUID        uuid.UUID `json:"uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	Username    string    `json:"username" gorm:"type:varchar(128)"`
	DisplayName string    `json:"displayName,omitempty" gorm:"column:display_name;type:varchar(256)"`
	Email       string    `json:"email,omitempty" gorm:"type:varchar(256)"`
	Phone       string    `json:"phone,omitempty" gorm:"type:varchar(32)"`
	Status      int16     `json:"status" gorm:"default:1"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Tenant struct {
	ID        int64     `json:"-" gorm:"primaryKey"`
	UUID      uuid.UUID `json:"uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	Code      string    `json:"code" gorm:"type:varchar(64)"`
	Name      string    `json:"name" gorm:"type:varchar(256)"`
	Status    int16     `json:"status" gorm:"default:1"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type TenantDomain struct {
	ID         int64     `json:"id" gorm:"primaryKey"`
	TenantID   int64     `json:"-"`
	Pattern    string    `json:"pattern" gorm:"type:varchar(512)"`
	IsWildcard bool      `json:"isWildcard" gorm:"column:is_wildcard;default:false"`
	CreatedAt  time.Time `json:"createdAt"`
}

type TenantUser struct {
	ID        int64     `json:"-" gorm:"primaryKey"`
	UserID    int64     `json:"-"`
	TenantID  int64     `json:"-"`
	Status    int16     `json:"status" gorm:"default:1"`
	CreatedAt time.Time `json:"createdAt"`
}

type Role struct {
	ID          int64     `json:"-" gorm:"primaryKey"`
	UUID        uuid.UUID `json:"uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	TenantID    int64     `json:"-"`
	Code        string    `json:"code" gorm:"type:varchar(64)"`
	Name        string    `json:"name" gorm:"type:varchar(256)"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Permission struct {
	ID          int64     `json:"-" gorm:"primaryKey"`
	UUID        uuid.UUID `json:"uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	TenantID    int64     `json:"-"`
	Code        string    `json:"code" gorm:"type:varchar(128)"`
	Name        string    `json:"name" gorm:"type:varchar(256)"`
	Resource    string    `json:"resource" gorm:"type:varchar(512)"`
	Action      string    `json:"action" gorm:"type:varchar(32)"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type UserRole struct {
	ID        int64     `json:"-" gorm:"primaryKey"`
	UserID    int64     `json:"-"`
	RoleID    int64     `json:"-"`
	TenantID  int64     `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
}

type RolePermission struct {
	ID           int64     `json:"-" gorm:"primaryKey"`
	RoleID       int64     `json:"-"`
	PermissionID int64     `json:"-"`
	CreatedAt    time.Time `json:"createdAt"`
}

type PaginationParams struct {
	Page     int
	PageSize int
}

type PaginatedResult[T any] struct {
	Data       []T        `json:"data"`
	Pagination Pagination `json:"pagination"`
}

type Pagination struct {
	Page     int `json:"page"`
	PageSize int `json:"pageSize"`
	Total    int `json:"total"`
}
```

---

### Task 3: Replace db.go connection layer

**Files:**
- Rewrite: `pkg/rbac/store/db.go`

- [ ] **Step 1: Replace the entire db.go content**

Replace the full content of `pkg/rbac/store/db.go` with:

```go
package store

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type DBConfig struct {
	DSN                    string
	MaxOpenConns           int
	MaxIdleConns           int
	ConnMaxLifetimeMinutes int
}

func NewDB(ctx context.Context, cfg DBConfig) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect to postgres: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
	if err := sqlDB.PingContext(ctx); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}
```

---

### Task 4: Migrate tenant_repo.go

**Files:**
- Rewrite: `pkg/rbac/store/tenant_repo.go`

- [ ] **Step 1: Replace the entire tenant_repo.go content**

Replace the full content of `pkg/rbac/store/tenant_repo.go` with:

```go
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
```

---

### Task 5: Migrate tenant_domain_repo.go

**Files:**
- Rewrite: `pkg/rbac/store/tenant_domain_repo.go`

- [ ] **Step 1: Replace the entire tenant_domain_repo.go content**

Replace the full content of `pkg/rbac/store/tenant_domain_repo.go` with:

```go
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
```

---

### Task 6: Migrate user_repo.go

**Files:**
- Rewrite: `pkg/rbac/store/user_repo.go`

- [ ] **Step 1: Replace the entire user_repo.go content**

Replace the full content of `pkg/rbac/store/user_repo.go` with:

```go
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
	query := r.db.WithContext(ctx).Model(&User{}).Where("status = ?", 1)
	if search != "" {
		pattern := "%" + search + "%"
		query = query.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", pattern, pattern, pattern)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []User
	if err := query.Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
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
```

---

### Task 7: Migrate role_repo.go

**Files:**
- Rewrite: `pkg/rbac/store/role_repo.go`

- [ ] **Step 1: Replace the entire role_repo.go content**

Replace the full content of `pkg/rbac/store/role_repo.go` with:

```go
package store

import (
	"context"
	"fmt"

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
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	role.TenantID = tenant.ID
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

func (r *RoleRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Role], error) {
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Role{}).Where("tenant_id = ?", tenant.ID).Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []Role
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenant.ID).Order("id").Limit(p.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[Role]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
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

func (r *RoleRepo) GetUserRolesInTenant(ctx context.Context, tenantUUID, userUUID uuid.UUID, p PaginationParams) (*PaginatedResult[Role], error) {
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}
	var user User
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&user).Error; err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Role{}).
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND user_roles.tenant_id = ?", user.ID, tenant.ID).
		Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (p.Page - 1) * p.PageSize
	var items []Role
	if err := r.db.WithContext(ctx).
		Joins("JOIN user_roles ON user_roles.role_id = roles.id").
		Where("user_roles.user_id = ? AND user_roles.tenant_id = ?", user.ID, tenant.ID).
		Order("roles.id").Limit(p.PageSize).Offset(offset).
		Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[Role]{
		Data:       items,
		Pagination: Pagination{Page: p.Page, PageSize: p.PageSize, Total: int(total)},
	}, nil
}

func (r *RoleRepo) SetUserRoles(ctx context.Context, tenantUUID, userUUID uuid.UUID, roleUUIDs []uuid.UUID) error {
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	var user User
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", userUUID).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ? AND tenant_id = ?", user.ID, tenant.ID).Delete(&UserRole{}).Error; err != nil {
			return err
		}
		for _, roleUID := range roleUUIDs {
			var role Role
			if err := tx.Select("id").Where("uuid = ? AND tenant_id = ?", roleUID, tenant.ID).First(&role).Error; err != nil {
				return err
			}
			ur := UserRole{UserID: user.ID, RoleID: role.ID, TenantID: tenant.ID}
			if err := tx.Create(&ur).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
```

---

### Task 8: Migrate permission_repo.go

**Files:**
- Rewrite: `pkg/rbac/store/permission_repo.go`

- [ ] **Step 1: Replace the entire permission_repo.go content**

Replace the full content of `pkg/rbac/store/permission_repo.go` with:

```go
package store

import (
	"context"
	"fmt"

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
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return fmt.Errorf("tenant not found: %w", err)
	}
	p.TenantID = tenant.ID
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

func (r *PermissionRepo) ListByTenant(ctx context.Context, tenantUUID uuid.UUID, pg PaginationParams) (*PaginatedResult[Permission], error) {
	var tenant Tenant
	if err := r.db.WithContext(ctx).Select("id").Where("uuid = ?", tenantUUID).First(&tenant).Error; err != nil {
		return nil, fmt.Errorf("tenant not found: %w", err)
	}

	var total int64
	if err := r.db.WithContext(ctx).Model(&Permission{}).Where("tenant_id = ?", tenant.ID).Count(&total).Error; err != nil {
		return nil, err
	}

	offset := (pg.Page - 1) * pg.PageSize
	var items []Permission
	if err := r.db.WithContext(ctx).Where("tenant_id = ?", tenant.ID).Order("id").Limit(pg.PageSize).Offset(offset).Find(&items).Error; err != nil {
		return nil, err
	}
	return &PaginatedResult[Permission]{
		Data:       items,
		Pagination: Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: int(total)},
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

func (r *PermissionRepo) GetRolePermissions(ctx context.Context, roleUUID uuid.UUID, pg PaginationParams) (*PaginatedResult[Permission], error) {
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
	return &PaginatedResult[Permission]{
		Data:       items,
		Pagination: Pagination{Page: pg.Page, PageSize: pg.PageSize, Total: int(total)},
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
```

---

### Task 9: Migrate seed.go

**Files:**
- Rewrite: `pkg/rbac/store/seed.go`

- [ ] **Step 1: Replace the entire seed.go content**

Replace the full content of `pkg/rbac/store/seed.go` with:

```go
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
```

---

### Task 10: Update rbac.go initialization

**Files:**
- Modify: `pkg/rbac/rbac.go`

- [ ] **Step 1: Update the import and New() function**

In `pkg/rbac/rbac.go`, make these changes:

Replace the full content of `pkg/rbac/rbac.go` with:

```go
package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"api-gateway/pkg/rbac/store"
)

type RBAC struct {
	cfg        Config
	enforcer   *Enforcer
	tenants    *DomainTrie
	tenantRepo *store.TenantRepo
	domainRepo *store.TenantDomainRepo
	userRepo   *store.UserRepo
	roleRepo   *store.RoleRepo
	permRepo   *store.PermissionRepo
}

func New(ctx context.Context, cfg Config) (*RBAC, error) {
	cfg.ApplyDefaults()

	dbCfg := store.DBConfig{
		DSN:                    cfg.DB.DSN,
		MaxOpenConns:           cfg.DB.MaxOpenConns,
		MaxIdleConns:           cfg.DB.MaxIdleConns,
		ConnMaxLifetimeMinutes: cfg.DB.ConnMaxLifetimeMinutes,
	}
	db, err := store.NewDB(ctx, dbCfg)
	if err != nil {
		return nil, fmt.Errorf("rbac db: %w", err)
	}

	slog.Info("running RBAC database migrations")
	if err := store.RunMigrations(cfg.DB.DSN); err != nil {
		return nil, fmt.Errorf("rbac migrations: %w", err)
	}

	slog.Info("seeding RBAC bootstrap data")
	if err := store.Seed(ctx, db, cfg.SuperAdmin.Username); err != nil {
		return nil, fmt.Errorf("rbac seed: %w", err)
	}

	slog.Info("initializing Casbin enforcer")
	enforcer, err := NewEnforcer(cfg.DB.DSN)
	if err != nil {
		return nil, fmt.Errorf("rbac enforcer: %w", err)
	}

	rc := &RBAC{
		cfg:        cfg,
		enforcer:   enforcer,
		tenants:    NewDomainTrie(),
		tenantRepo: store.NewTenantRepo(db),
		domainRepo: store.NewTenantDomainRepo(db),
		userRepo:   store.NewUserRepo(db),
		roleRepo:   store.NewRoleRepo(db),
		permRepo:   store.NewPermissionRepo(db),
	}

	if err := rc.RefreshTenantMap(ctx); err != nil {
		return nil, fmt.Errorf("rbac tenant map: %w", err)
	}

	slog.Info("RBAC module initialized", "adminPath", cfg.AdminPath)
	return rc, nil
}

func (rc *RBAC) Enforce(sub, dom, obj, act string) (bool, error) {
	return rc.enforcer.Enforce(sub, dom, obj, act)
}

func (rc *RBAC) ReloadPolicy() error {
	return rc.enforcer.LoadPolicy()
}

func (rc *RBAC) AdminHandler() http.Handler {
	return rc.adminRoutes()
}

func (rc *RBAC) autoProvisionUser(ctx context.Context, username, email, phone string) {
	u := &store.User{
		Username: username,
		Email:    email,
		Phone:    phone,
	}
	if err := rc.userRepo.Upsert(ctx, u); err != nil {
		slog.Error("auto-provision user failed", "error", err, "username", username)
	}
}
```

Note: `store.NewDB` returns `*gorm.DB`, but Go infers the type via `:=` assignment, so `rbac.go` does not need to import `gorm.io/gorm` directly.

---

### Task 11: Build verification and cleanup

**Files:**
- Verify: all modified files

- [ ] **Step 1: Tidy modules**

Run:
```bash
go mod tidy
```

Expected: clean exit, `go.sum` updated. `pgx/v5` should now be an indirect dependency (pulled in transitively by the postgres driver) rather than direct.

- [ ] **Step 2: Build the project**

Run:
```bash
go build ./...
```

Expected: clean compilation with no errors.

- [ ] **Step 3: Vet the project**

Run:
```bash
go vet ./...
```

Expected: no issues.

- [ ] **Step 4: Fix any compilation errors**

If there are compilation errors, fix them. Common issues to check:
- Unused imports (remove `pgx`, `pgxpool`, `fmt` where no longer needed)
- Type mismatches (`int64` vs `int` for count/total)
- Missing `gorm.io/gorm/clause` import in files using `clause.OnConflict`

- [ ] **Step 5: Commit all changes**

```bash
git add pkg/rbac/store/models.go pkg/rbac/store/db.go pkg/rbac/store/tenant_repo.go pkg/rbac/store/tenant_domain_repo.go pkg/rbac/store/user_repo.go pkg/rbac/store/role_repo.go pkg/rbac/store/permission_repo.go pkg/rbac/store/seed.go pkg/rbac/rbac.go go.mod go.sum
git commit -m "refactor(rbac): migrate data access layer from raw SQL to GORM"
```
