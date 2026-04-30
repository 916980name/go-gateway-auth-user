package store

import (
	"time"

	"github.com/google/uuid"
)

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

type tenantRef struct {
	ID int64 `gorm:"primaryKey"`
}

func (tenantRef) TableName() string { return "tenants" }

type userRef struct {
	ID int64 `gorm:"primaryKey"`
}

func (userRef) TableName() string { return "users" }

