package store

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID          int64     `json:"-" gorm:"primaryKey"`
	UUID        uuid.UUID `json:"uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	TenantID    int64     `json:"-"`
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
	UUID      uuid.UUID `json:"tenant_uuid" gorm:"type:uuid;default:gen_random_uuid()"`
	Code      string    `json:"code" gorm:"type:varchar(64)"`
	Name      string    `json:"name" gorm:"type:varchar(256)"`
	Status    int16     `json:"status" gorm:"default:1"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type TenantDomain struct {
	ID         int64     `json:"-" gorm:"primaryKey"`
	TenantID   int64     `json:"-"`
	Pattern    string    `json:"pattern" gorm:"type:varchar(512)"`
	IsWildcard bool      `json:"isWildcard" gorm:"column:is_wildcard;default:false"`
	CreatedAt  time.Time `json:"createdAt"`
}

type UserCredential struct {
	ID           int64     `json:"-" gorm:"primaryKey"`
	UserID       int64     `json:"-"`
	TenantID     int64     `json:"-"`
	ProviderType string    `json:"providerType" gorm:"type:varchar(32)"`
	Credential   string    `json:"-" gorm:"type:text"`
	Identifier   *string   `json:"identifier,omitempty" gorm:"type:varchar(256)"`
	Metadata     *string   `json:"metadata,omitempty" gorm:"type:jsonb"`
	Status       int16     `json:"status" gorm:"default:1"`
	CreatedAt    time.Time `json:"createdAt"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

