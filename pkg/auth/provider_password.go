package auth

import (
	"context"
	"errors"

	"api-gateway/pkg/user/store"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type PasswordProvider struct {
	userRepo *store.UserRepo
	credRepo *store.CredentialRepo
}

func NewPasswordProvider(userRepo *store.UserRepo, credRepo *store.CredentialRepo) *PasswordProvider {
	return &PasswordProvider{userRepo: userRepo, credRepo: credRepo}
}

func (p *PasswordProvider) Type() string { return "password" }

func (p *PasswordProvider) Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	user, err := p.userRepo.FindByIdentifier(ctx, req.TenantID, req.Identifier)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	cred, err := p.credRepo.GetByUserAndProvider(ctx, user.ID, req.TenantID, "password")
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if cred.Status == 0 {
		return nil, ErrCredentialDisabled
	}

	if err := bcrypt.CompareHashAndPassword([]byte(cred.Credential), []byte(req.Credential)); err != nil {
		return nil, ErrInvalidCredentials
	}

	return &AuthResult{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Phone:    user.Phone,
		TenantID: user.TenantID,
	}, nil
}
