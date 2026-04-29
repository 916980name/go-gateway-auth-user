package store

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          int64     `json:"-"`
	UUID        uuid.UUID `json:"uuid"`
	Username    string    `json:"username"`
	DisplayName string    `json:"displayName,omitempty"`
	Email       string    `json:"email,omitempty"`
	Phone       string    `json:"phone,omitempty"`
	Status      int16     `json:"status"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Tenant struct {
	ID        int64     `json:"-"`
	UUID      uuid.UUID `json:"uuid"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Hostname  string    `json:"hostname"`
	Status    int16     `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type TenantUser struct {
	ID        int64     `json:"-"`
	UserID    int64     `json:"-"`
	TenantID  int64     `json:"-"`
	Status    int16     `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
}

type Role struct {
	ID          int64     `json:"-"`
	UUID        uuid.UUID `json:"uuid"`
	TenantID    int64     `json:"-"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type Permission struct {
	ID          int64     `json:"-"`
	UUID        uuid.UUID `json:"uuid"`
	TenantID    int64     `json:"-"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Resource    string    `json:"resource"`
	Action      string    `json:"action"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type UserRole struct {
	ID        int64     `json:"-"`
	UserID    int64     `json:"-"`
	RoleID    int64     `json:"-"`
	TenantID  int64     `json:"-"`
	CreatedAt time.Time `json:"createdAt"`
}

type RolePermission struct {
	ID           int64     `json:"-"`
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
