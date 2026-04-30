package auth

import (
	"context"
	"errors"
	"testing"

	"api-gateway/pkg/user"
)

type mockProvider struct {
	authFunc func(ctx context.Context, req AuthRequest) (*AuthResult, error)
}

func (m *mockProvider) Type() string { return "mock" }
func (m *mockProvider) Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error) {
	return m.authFunc(ctx, req)
}

func TestModuleAuthenticate_Success(t *testing.T) {
	mod := New(Config{}, &user.Module{})
	mod.RegisterProvider(&mockProvider{
		authFunc: func(ctx context.Context, req AuthRequest) (*AuthResult, error) {
			return &AuthResult{UserID: 1, Username: "alice", TenantID: 10}, nil
		},
	})

	result, err := mod.Authenticate(context.Background(), AuthRequest{
		TenantID:   10,
		Provider:   "mock",
		Identifier: "alice",
		Credential: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Username != "alice" {
		t.Errorf("expected username alice, got %s", result.Username)
	}
	if result.TenantID != 10 {
		t.Errorf("expected tenant 10, got %d", result.TenantID)
	}
}

func TestModuleAuthenticate_ProviderNotFound(t *testing.T) {
	mod := New(Config{}, &user.Module{})

	_, err := mod.Authenticate(context.Background(), AuthRequest{
		Provider:   "nonexistent",
		Identifier: "alice",
		Credential: "secret",
	})
	if !errors.Is(err, ErrProviderNotFound) {
		t.Errorf("expected ErrProviderNotFound, got %v", err)
	}
}

func TestModuleAuthenticate_ProviderReturnsError(t *testing.T) {
	mod := New(Config{}, &user.Module{})
	mod.RegisterProvider(&mockProvider{
		authFunc: func(ctx context.Context, req AuthRequest) (*AuthResult, error) {
			return nil, ErrInvalidCredentials
		},
	})

	_, err := mod.Authenticate(context.Background(), AuthRequest{
		Provider:   "mock",
		Identifier: "alice",
		Credential: "wrong",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestModuleHasProvider(t *testing.T) {
	mod := New(Config{}, &user.Module{})
	mod.RegisterProvider(&mockProvider{
		authFunc: func(ctx context.Context, req AuthRequest) (*AuthResult, error) {
			return nil, nil
		},
	})

	if !mod.HasProvider("mock") {
		t.Error("expected HasProvider(mock) to be true")
	}
	if mod.HasProvider("password") {
		t.Error("expected HasProvider(password) to be false")
	}
}
