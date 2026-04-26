package middleware

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRefreshTokenHandler_ExpiredAccessToken(t *testing.T) {
	payload := map[string]interface{}{
		"username":   "testuser",
		"privileges": "admin",
		"idKey":      "uid-001",
	}
	accessToken, err := jwt.GenerateJWTRSA(payload, 1*time.Millisecond, testPrivateKey)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	refreshToken, err := jwt.GenerateJWTRSA(payload, 1*time.Hour, testPrivateKey)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	handler := NewRefreshTokenHandler(nil, testPublicKey, testPrivateKey, false)
	chain := handler(nil)

	r := httptest.NewRequest("GET", "/refreshToken", nil)
	r.Header.Set("Authorization", "Bearer "+accessToken)
	r.Header.Set("Refresh", refreshToken)

	_, resp, err := chain(context.Background(), r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200 response, got %v", resp)
	}
	newToken := resp.Header.Get(HEADER_ACCESS_TOKEN)
	if newToken == "" {
		t.Error("expected new access token in response header")
	}
}

func TestRefreshTokenHandler_InvalidAccessToken(t *testing.T) {
	payload := map[string]interface{}{
		"username":   "testuser",
		"privileges": "admin",
		"idKey":      "uid-001",
	}
	refreshToken, err := jwt.GenerateJWTRSA(payload, 1*time.Hour, testPrivateKey)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	handler := NewRefreshTokenHandler(nil, testPublicKey, testPrivateKey, false)
	chain := handler(nil)

	r := httptest.NewRequest("GET", "/refreshToken", nil)
	r.Header.Set("Authorization", "Bearer invalid.token.here")
	r.Header.Set("Refresh", refreshToken)

	_, _, err = chain(context.Background(), r)
	if err == nil {
		t.Fatal("expected error for invalid access token, got nil")
	}
	herr, ok := err.(*common.HTTPError)
	if !ok {
		t.Fatalf("expected *common.HTTPError, got %T", err)
	}
	if herr.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", herr.Status, http.StatusUnauthorized)
	}
}

func TestRefreshTokenHandler_MissingRefreshHeader(t *testing.T) {
	payload := map[string]interface{}{
		"username":   "testuser",
		"privileges": "admin",
		"idKey":      "uid-001",
	}
	accessToken, err := jwt.GenerateJWTRSA(payload, 1*time.Millisecond, testPrivateKey)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	handler := NewRefreshTokenHandler(nil, testPublicKey, testPrivateKey, false)
	chain := handler(nil)

	r := httptest.NewRequest("GET", "/refreshToken", nil)
	r.Header.Set("Authorization", "Bearer "+accessToken)

	_, _, err = chain(context.Background(), r)
	if err == nil {
		t.Fatal("expected error for missing refresh token, got nil")
	}
	herr, ok := err.(*common.HTTPError)
	if !ok {
		t.Fatalf("expected *common.HTTPError, got %T", err)
	}
	if herr.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", herr.Status, http.StatusUnauthorized)
	}
}

func TestRefreshTokenHandler_ValidAccessToken(t *testing.T) {
	payload := map[string]interface{}{
		"username":   "testuser",
		"privileges": "admin",
		"idKey":      "uid-001",
	}
	accessToken, err := jwt.GenerateJWTRSA(payload, 1*time.Hour, testPrivateKey)
	if err != nil {
		t.Fatalf("generate access token: %v", err)
	}
	refreshToken, err := jwt.GenerateJWTRSA(payload, 24*time.Hour, testPrivateKey)
	if err != nil {
		t.Fatalf("generate refresh token: %v", err)
	}

	handler := NewRefreshTokenHandler(nil, testPublicKey, testPrivateKey, false)
	chain := handler(nil)

	r := httptest.NewRequest("GET", "/refreshToken", nil)
	r.Header.Set("Authorization", "Bearer "+accessToken)
	r.Header.Set("Refresh", refreshToken)

	_, resp, err := chain(context.Background(), r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %v", resp)
	}
	newToken := resp.Header.Get(HEADER_ACCESS_TOKEN)
	if newToken == "" {
		t.Error("expected new access token")
	}
}
