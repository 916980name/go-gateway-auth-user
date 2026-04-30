package rbac

import (
	"net/http"

	"api-gateway/pkg/rbac/handler"
)

func (rc *RBAC) adminRoutes() http.Handler {
	mux := http.NewServeMux()

	pgCfg := handler.PaginationConfig{
		DefaultPageSize: rc.cfg.Pagination.DefaultPageSize,
		MaxPageSize:     rc.cfg.Pagination.MaxPageSize,
	}

	rh := handler.NewRoleHandler(rc.roleRepo, pgCfg, func() { rc.ReloadPolicy() })
	ph := handler.NewPermissionHandler(rc.permRepo, pgCfg, func() { rc.ReloadPolicy() })

	mux.HandleFunc("GET /tenants/{tenantId}/roles", rh.List)
	mux.HandleFunc("POST /tenants/{tenantId}/roles", rh.Create)
	mux.HandleFunc("PUT /tenants/{tenantId}/roles/{id}", rh.Update)
	mux.HandleFunc("DELETE /tenants/{tenantId}/roles/{id}", rh.Delete)
	mux.HandleFunc("GET /tenants/{tenantId}/roles/{id}/permissions", ph.GetRolePermissions)
	mux.HandleFunc("PUT /tenants/{tenantId}/roles/{id}/permissions", ph.SetRolePermissions)

	mux.HandleFunc("GET /tenants/{tenantId}/users/{userId}/roles", rh.GetUserRoles)
	mux.HandleFunc("PUT /tenants/{tenantId}/users/{userId}/roles", rh.SetUserRoles)

	mux.HandleFunc("GET /tenants/{tenantId}/permissions", ph.List)
	mux.HandleFunc("POST /tenants/{tenantId}/permissions", ph.Create)
	mux.HandleFunc("PUT /tenants/{tenantId}/permissions/{id}", ph.Update)
	mux.HandleFunc("DELETE /tenants/{tenantId}/permissions/{id}", ph.Delete)

	return mux
}
