package middleware

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"context"
	"net/http"

	"go-user-manage/pkg/gwperm"
)

func PermFilter(permClient *gwperm.Client) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			username, _ := ctx.Value(gwperm.CtxKeyUsername).(string)
			if username == "" {
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}

			// Resolve tenant from hostname
			tenantCode, _ := ctx.Value(gwperm.CtxKeyTenantCode).(string)
			if tenantCode == "" {
				tenantInfo, ok := permClient.ResolveTenant(r.Host)
				if !ok || tenantInfo == nil {
					log.C(ctx).Warnw("unknown tenant for host", "host", r.Host)
					return ctx, nil, common.NewHTTPError("Forbidden: unknown domain", http.StatusForbidden)
				}
				tenantCode = tenantInfo.Code
				ctx = context.WithValue(ctx, gwperm.CtxKeyTenantCode, tenantInfo.Code)
				ctx = context.WithValue(ctx, gwperm.CtxKeyTenantUUID, tenantInfo.UUID)
			}

			// Validate JWT tenant UUID matches resolved tenant (if present)
			if jwtTenant, _ := ctx.Value(common.Trace_request_tenant_uuid{}).(string); jwtTenant != "" {
				resolvedUUID, _ := ctx.Value(gwperm.CtxKeyTenantUUID).(string)
				if resolvedUUID != "" && jwtTenant != resolvedUUID {
					return ctx, nil, common.NewHTTPError("Forbidden: tenant mismatch", http.StatusForbidden)
				}
			}

			allowed, err := permClient.Enforce(username, tenantCode, r.URL.Path, r.Method)
			if err != nil {
				log.C(ctx).Errorw("permission check failed", "error", err, "user", username, "tenant", tenantCode, "path", r.URL.Path)
				return ctx, nil, common.NewHTTPError("Internal Server Error", http.StatusInternalServerError)
			}
			if !allowed {
				log.C(ctx).Warnw("permission denied", "user", username, "tenant", tenantCode, "path", r.URL.Path, "method", r.Method)
				return ctx, nil, common.NewHTTPError("Forbidden", http.StatusForbidden)
			}

			return next(ctx, r)
		}
	}
}
