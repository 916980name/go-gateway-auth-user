package auth

import (
	"context"
	"log/slog"

	"api-gateway/pkg/user"
)

type Module struct {
	providers map[string]CredentialProvider
	userMod   *user.Module
}

func New(cfg Config, userMod *user.Module) *Module {
	m := &Module{
		providers: make(map[string]CredentialProvider),
		userMod:   userMod,
	}

	for _, pc := range cfg.Providers {
		switch pc.Type {
		case "password":
			m.RegisterProvider(NewPasswordProvider(userMod.UserRepo(), userMod.CredentialRepo()))
		default:
			slog.Warn("unknown auth provider type, skipping", "type", pc.Type)
		}
	}

	slog.Info("auth module initialized", "providers", len(m.providers))
	return m
}

func (m *Module) RegisterProvider(p CredentialProvider) {
	m.providers[p.Type()] = p
}

func (m *Module) Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	p, ok := m.providers[req.Provider]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return p.Authenticate(ctx, req)
}

func (m *Module) UserModule() *user.Module {
	return m.userMod
}

func (m *Module) HasProvider(providerType string) bool {
	_, ok := m.providers[providerType]
	return ok
}
