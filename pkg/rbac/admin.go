package rbac

import (
	"net/http"

	"api-gateway/pkg/common"
	"api-gateway/pkg/rbac/handler"
)

func (rc *RBAC) adminRoutes() http.Handler {
	mux := http.NewServeMux()
	rc.adminRoutesOn(mux)
	return mux
}

func (rc *RBAC) adminRoutesOn(mux *http.ServeMux) {

	pgCfg := common.DefaultPagination()

	rh := handler.NewRoleHandler(rc.roleRepo, pgCfg, func() { rc.ReloadPolicy() })
	ph := handler.NewPermissionHandler(rc.permRepo, pgCfg, func() { rc.ReloadPolicy() })

	// Tenant-scoped admin routes (tenant resolved from domain context)
	mux.HandleFunc("GET /roles", rh.List)
	mux.HandleFunc("POST /roles", rh.Create)
	mux.HandleFunc("PUT /roles/{id}", rh.Update)
	mux.HandleFunc("DELETE /roles/{id}", rh.Delete)
	mux.HandleFunc("GET /roles/{id}/permissions", ph.GetRolePermissions)
	mux.HandleFunc("PUT /roles/{id}/permissions", ph.SetRolePermissions)

	mux.HandleFunc("GET /users/{userId}/roles", rh.GetUserRoles)
	mux.HandleFunc("PUT /users/{userId}/roles", rh.SetUserRoles)

	mux.HandleFunc("GET /permissions", ph.List)
	mux.HandleFunc("POST /permissions", ph.Create)
	mux.HandleFunc("PUT /permissions/{id}", ph.Update)
	mux.HandleFunc("DELETE /permissions/{id}", ph.Delete)
}
