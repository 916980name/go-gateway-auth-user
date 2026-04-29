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
