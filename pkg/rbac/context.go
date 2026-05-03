package rbac

type contextKey struct{ name string }

var (
	CtxKeyUsername   = &contextKey{"rbac-username"}
	CtxKeyEmail      = &contextKey{"rbac-email"}
	CtxKeyPhone      = &contextKey{"rbac-phone"}
	CtxKeyUserID     = &contextKey{"rbac-userid"}
	CtxKeyDomain     = &contextKey{"rbac-domain"}
	CtxKeyTenantUUID = &contextKey{"rbac-tenant-uuid"}
	CtxKeyTenantCode = &contextKey{"rbac-tenant-code"}
)
