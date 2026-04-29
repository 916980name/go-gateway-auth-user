package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"testing"

	"api-gateway/pkg/jwt"
	"api-gateway/pkg/proxy"
)

func TestAuthFilterRBACEnabledSkipsPrivilegeCheck(t *testing.T) {
	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &priKey.PublicKey

	payload := map[string]interface{}{
		"username":   "alice",
		"privileges": "",
	}
	token, err := jwt.GenerateJWTRSA(payload, 60*1000*1000*1000, priKey)
	if err != nil {
		t.Fatal(err)
	}

	authR := AuthRequirements{
		Privileges:  "admin",
		PubKey:      pubKey,
		PriKey:      priKey,
		RBACEnabled: true,
	}

	nextCalled := false
	next := proxy.Proxy(func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		nextCalled = true
		return ctx, &http.Response{StatusCode: 200}, nil
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	chain := AuthFilter(authR)(next)
	_, _, err = chain(context.Background(), req)
	if err != nil {
		t.Fatalf("expected no error with RBAC enabled, got: %v", err)
	}
	if !nextCalled {
		t.Error("next handler should have been called when RBAC is enabled (privilege check skipped)")
	}
}

func TestAuthFilterRBACDisabledEnforcesPrivileges(t *testing.T) {
	priKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubKey := &priKey.PublicKey

	payload := map[string]interface{}{
		"username":   "alice",
		"privileges": "viewer",
	}
	token, err := jwt.GenerateJWTRSA(payload, 60*1000*1000*1000, priKey)
	if err != nil {
		t.Fatal(err)
	}

	authR := AuthRequirements{
		Privileges:  "admin",
		PubKey:      pubKey,
		PriKey:      priKey,
		RBACEnabled: false,
	}

	next := proxy.Proxy(func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		t.Error("next should NOT be called when user lacks privilege with RBAC disabled")
		return ctx, &http.Response{StatusCode: 200}, nil
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	chain := AuthFilter(authR)(next)
	_, _, err = chain(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when user lacks privilege with RBAC disabled")
	}
}
