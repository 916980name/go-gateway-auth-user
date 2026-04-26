package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCheckCouldPass_NilRateLimiterConfig(t *testing.T) {
	lfr := &LoginFilterRequirements{
		BlacklistRateLimiterConfig: nil,
	}
	pass, err := checkCouldPass(context.Background(), "1.2.3.4", lfr)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !pass {
		t.Error("expected pass=true when BlacklistRateLimiterConfig is nil")
	}
}

func TestLogoutFilter_NilUserContext(t *testing.T) {
	mc, _ := cache.NewMemCache("test-logout", 100, 10*time.Minute)
	logoutF := LogoutFilter(&LogoutFilterRequirements{
		OnlineCache:   &mc,
		LogoutPath:    "/logout",
		CookieEnabled: false,
	})
	dummyNext := func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
		return ctx, &http.Response{
			StatusCode: 200,
			Header:     http.Header{},
			Body:       io.NopCloser(bytes.NewReader(nil)),
		}, nil
	}

	chain := logoutF(dummyNext)
	r := httptest.NewRequest("POST", "/logout", nil)
	r.Header.Set("Authorization", "Bearer some-token")

	_, _, err := chain(context.Background(), r)
	if err == nil {
		t.Fatal("expected error when user not in context, got nil")
	}
	herr, ok := err.(*common.HTTPError)
	if !ok {
		t.Fatalf("expected *common.HTTPError, got %T", err)
	}
	if herr.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", herr.Status, http.StatusUnauthorized)
	}
}

func TestAttentionIP_NilRateLimiterConfig(t *testing.T) {
	lfr := &LoginFilterRequirements{
		BlacklistRateLimiterConfig: nil,
	}
	pass, err := attentionIP(context.Background(), lfr, "1.2.3.4")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !pass {
		t.Error("expected pass=true when BlacklistRateLimiterConfig is nil")
	}
}
