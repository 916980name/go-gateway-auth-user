package auth

import (
	"context"
	"errors"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrProviderNotFound   = errors.New("provider not supported")
	ErrUserDisabled       = errors.New("user account is disabled")
	ErrCredentialDisabled = errors.New("credential is disabled")
)

type AuthRequest struct {
	TenantID   int64
	Provider   string
	Identifier string
	Credential string
}

type AuthResult struct {
	UserID   int64
	Username string
	Email    string
	Phone    string
	TenantID int64
}

type CredentialProvider interface {
	Type() string
	Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error)
}
