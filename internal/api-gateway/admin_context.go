package gateway

import (
	"net/http"

	"api-gateway/pkg/rbac"
	rbacHandler "api-gateway/pkg/rbac/handler"
)

func adminContextBridge(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if v, ok := ctx.Value(rbac.CtxKeyTenantUUID).(string); ok && v != "" {
			ctx = rbacHandler.SetTenantUUIDInCtx(ctx, v)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
