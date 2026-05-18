package middleware

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"

	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"

	"go-user-manage/pkg/gwperm"
)

type AdminAuthConfig struct {
	PublicKey *rsa.PublicKey
}

func AdminAuthFilter(cfg AdminAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := getBearerToken(r)
			if err != nil {
				writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid token")
				return
			}

			payload, err := jwt.VerifyJWTRSA(token, cfg.PublicKey)
			if err != nil {
				writeAdminError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token")
				return
			}

			claims := extractAdminClaims(payload)
			ctx := r.Context()
			ctx = context.WithValue(ctx, gwperm.CtxKeyUsername, claims.Username)
			if claims.TenantUUID != "" {
				ctx = context.WithValue(ctx, gwperm.CtxKeyTenantUUID, claims.TenantUUID)
			}
			ctx = context.WithValue(ctx, common.Trace_request_user{}, claims.Username)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type adminClaims struct {
	Username   string `json:"username"`
	TenantUUID string `json:"tenant_uuid"`
}

func extractAdminClaims(payload interface{}) adminClaims {
	var claims adminClaims
	b, err := json.Marshal(payload)
	if err != nil {
		return claims
	}
	json.Unmarshal(b, &claims)
	return claims
}

func getBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		cookie, err := r.Cookie("Authorization")
		if err == nil {
			authHeader = "Bearer " + cookie.Value
		}
	}
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", http.ErrNoCookie
	}
	return parts[1], nil
}

func writeAdminError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
