package rbac

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMiddlewareMissingUsername(t *testing.T) {
	rc := &RBAC{
		tenants: newTenantMap(),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called without username")
	})

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()
	rc.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestMiddlewareUnknownTenant(t *testing.T) {
	rc := &RBAC{
		tenants: newTenantMap(),
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next should not be called for unknown tenant")
	})

	req := httptest.NewRequest("GET", "http://unknown.example.com/api/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxKeyUsername, "alice"))
	w := httptest.NewRecorder()
	rc.Middleware(next).ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}

	var resp map[string]map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"]["code"] != "UNKNOWN_TENANT" {
		t.Errorf("expected UNKNOWN_TENANT, got %s", resp["error"]["code"])
	}
}

func TestTenantMapOperations(t *testing.T) {
	m := newTenantMap()

	_, ok := m.Get("app.example.com")
	if ok {
		t.Error("expected not found for empty map")
	}

	m.Replace(map[string]string{
		"app.example.com": "site-a",
		"api.example.com": "site-b",
	})

	code, ok := m.Get("app.example.com")
	if !ok || code != "site-a" {
		t.Errorf("expected site-a, got %s (found: %v)", code, ok)
	}

	code, ok = m.Get("api.example.com")
	if !ok || code != "site-b" {
		t.Errorf("expected site-b, got %s (found: %v)", code, ok)
	}

	m.Replace(map[string]string{"new.example.com": "site-c"})
	_, ok = m.Get("app.example.com")
	if ok {
		t.Error("old entry should be gone after Replace")
	}
}
