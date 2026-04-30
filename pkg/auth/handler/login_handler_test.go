package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"api-gateway/pkg/auth"
	"api-gateway/pkg/user"
)

func newTestAuthModule(provider auth.CredentialProvider) *auth.Module {
	mod := auth.New(auth.Config{}, &user.Module{})
	if provider != nil {
		mod.RegisterProvider(provider)
	}
	return mod
}

func TestLoginHandler_MethodNotAllowed(t *testing.T) {
	h := NewLoginHandler(newTestAuthModule(nil), LoginHandlerConfig{})
	req := httptest.NewRequest("GET", "/auth/login", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	h := NewLoginHandler(newTestAuthModule(nil), LoginHandlerConfig{})
	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader("not json"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestLoginHandler_MissingFields(t *testing.T) {
	h := NewLoginHandler(newTestAuthModule(nil), LoginHandlerConfig{})

	tests := []struct {
		name string
		body string
	}{
		{"missing provider", `{"identifier":"alice","credential":"pass"}`},
		{"missing identifier", `{"provider":"password","credential":"pass"}`},
		{"missing credential", `{"provider":"password","identifier":"alice"}`},
		{"all empty", `{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(tt.body))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d", w.Code)
			}

			var resp map[string]map[string]string
			json.NewDecoder(w.Body).Decode(&resp)
			if resp["error"]["code"] != "INVALID_INPUT" {
				t.Errorf("expected INVALID_INPUT, got %s", resp["error"]["code"])
			}
		})
	}
}

func TestLoginHandler_UnknownDomain(t *testing.T) {
	h := NewLoginHandler(newTestAuthModule(nil), LoginHandlerConfig{})
	body := `{"provider":"password","identifier":"alice","credential":"pass123"}`
	req := httptest.NewRequest("POST", "http://unknown.example.com/auth/login", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"]["code"] != "UNKNOWN_DOMAIN" {
		t.Errorf("expected UNKNOWN_DOMAIN, got %s", resp["error"]["code"])
	}
}

func TestLogoutHandler_MethodNotAllowed(t *testing.T) {
	h := NewLogoutHandler(LogoutHandlerConfig{})
	req := httptest.NewRequest("GET", "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestLogoutHandler_MissingToken(t *testing.T) {
	h := NewLogoutHandler(LogoutHandlerConfig{})
	req := httptest.NewRequest("POST", "/auth/logout", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}
