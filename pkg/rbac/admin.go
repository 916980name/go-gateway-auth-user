package rbac

import (
	"context"
	"net/http"

	"api-gateway/pkg/rbac/handler"
)

func (rc *RBAC) adminRoutes() http.Handler {
	mux := http.NewServeMux()

	pgCfg := handler.PaginationConfig{
		DefaultPageSize: rc.cfg.Pagination.DefaultPageSize,
		MaxPageSize:     rc.cfg.Pagination.MaxPageSize,
	}
	th := handler.NewTenantHandler(rc.tenantRepo, pgCfg, func() { rc.onTenantChange() })
	dh := handler.NewTenantDomainHandler(rc.domainRepo, rc.tenantRepo, func() { rc.onTenantChange() })
	uh := handler.NewUserHandler(rc.userRepo, pgCfg)
	rh := handler.NewRoleHandler(rc.roleRepo, pgCfg, func() { rc.ReloadPolicy() })
	ph := handler.NewPermissionHandler(rc.permRepo, pgCfg, func() { rc.ReloadPolicy() })

	// Tenant management
	mux.HandleFunc("GET /tenants", th.List)
	mux.HandleFunc("POST /tenants", th.Create)
	mux.HandleFunc("GET /tenants/{id}", th.Get)
	mux.HandleFunc("PUT /tenants/{id}", th.Update)
	mux.HandleFunc("DELETE /tenants/{id}", th.Delete)

	// Tenant domain management
	mux.HandleFunc("GET /tenants/{id}/domains", dh.List)
	mux.HandleFunc("POST /tenants/{id}/domains", dh.Create)
	mux.HandleFunc("DELETE /tenants/{id}/domains/{domainId}", dh.Delete)

	// User management
	mux.HandleFunc("GET /users", uh.List)
	mux.HandleFunc("POST /users", uh.Create)
	mux.HandleFunc("GET /users/{id}", uh.Get)
	mux.HandleFunc("PUT /users/{id}", uh.Update)
	mux.HandleFunc("DELETE /users/{id}", uh.Delete)
	mux.HandleFunc("GET /users/{id}/tenants", uh.ListTenants)
	mux.HandleFunc("POST /users/{id}/tenants/{tenantId}", uh.AddToTenant)
	mux.HandleFunc("DELETE /users/{id}/tenants/{tenantId}", uh.RemoveFromTenant)

	// Role management (tenant-scoped)
	mux.HandleFunc("GET /tenants/{tenantId}/roles", rh.List)
	mux.HandleFunc("POST /tenants/{tenantId}/roles", rh.Create)
	mux.HandleFunc("PUT /tenants/{tenantId}/roles/{id}", rh.Update)
	mux.HandleFunc("DELETE /tenants/{tenantId}/roles/{id}", rh.Delete)
	mux.HandleFunc("GET /tenants/{tenantId}/roles/{id}/permissions", ph.GetRolePermissions)
	mux.HandleFunc("PUT /tenants/{tenantId}/roles/{id}/permissions", ph.SetRolePermissions)

	// User role assignment (tenant-scoped)
	mux.HandleFunc("GET /tenants/{tenantId}/users/{userId}/roles", rh.GetUserRoles)
	mux.HandleFunc("PUT /tenants/{tenantId}/users/{userId}/roles", rh.SetUserRoles)

	// Permission management (tenant-scoped)
	mux.HandleFunc("GET /tenants/{tenantId}/permissions", ph.List)
	mux.HandleFunc("POST /tenants/{tenantId}/permissions", ph.Create)
	mux.HandleFunc("PUT /tenants/{tenantId}/permissions/{id}", ph.Update)
	mux.HandleFunc("DELETE /tenants/{tenantId}/permissions/{id}", ph.Delete)

	return mux
}

func (rc *RBAC) onTenantChange() {
	rc.RefreshTenantMap(context.Background())
	rc.ReloadPolicy()
}
