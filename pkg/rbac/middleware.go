package rbac

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

func (rc *RBAC) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, _ := r.Context().Value(CtxKeyUsername).(string)
		if username == "" {
			writeJSONError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing user identity")
			return
		}

		hostname := r.Host
		tenantCode, ok := rc.resolveTenant(hostname)
		if !ok {
			writeJSONError(w, http.StatusForbidden, "UNKNOWN_TENANT", "unknown domain: "+hostname)
			return
		}

		rc.autoProvisionUser(r.Context(), tenantCode, username,
			stringFromCtx(r, CtxKeyEmail),
			stringFromCtx(r, CtxKeyPhone),
		)

		path := r.URL.Path
		method := r.Method
		allowed, err := rc.enforcer.Enforce(username, tenantCode, path, method)
		if err != nil {
			slog.Error("casbin enforce error", "error", err, "user", username, "tenant", tenantCode, "path", path, "method", method)
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "permission check failed")
			return
		}
		if !allowed {
			writeJSONError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
			return
		}

		next.ServeHTTP(w, r)
	})
}

func stringFromCtx(r *http.Request, key *contextKey) string {
	v, _ := r.Context().Value(key).(string)
	return v
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
