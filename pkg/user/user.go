package user

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"api-gateway/pkg/user/handler"
	"api-gateway/pkg/user/store"

	rbacstore "api-gateway/pkg/rbac/store"

	"gorm.io/gorm"
)

type Module struct {
	cfg          Config
	tenants      *DomainTrie
	userRepo     *store.UserRepo
	tenantRepo   *store.TenantRepo
	domainRepo   *store.TenantDomainRepo
	credRepo     *store.CredentialRepo
	db           *gorm.DB
	rbacRoleRepo *rbacstore.RoleRepo
	adminPath    string
}

func New(ctx context.Context, cfg Config) (*Module, error) {
	cfg.ApplyDefaults()

	dbCfg := store.DBConfig{
		DSN:                    cfg.DB.DSN,
		MaxOpenConns:           cfg.DB.MaxOpenConns,
		MaxIdleConns:           cfg.DB.MaxIdleConns,
		ConnMaxLifetimeMinutes: cfg.DB.ConnMaxLifetimeMinutes,
	}
	db, err := store.NewDB(ctx, dbCfg)
	if err != nil {
		return nil, fmt.Errorf("user db: %w", err)
	}

	m := &Module{
		cfg:        cfg,
		tenants:    NewDomainTrie(),
		userRepo:   store.NewUserRepo(db),
		tenantRepo: store.NewTenantRepo(db),
		domainRepo: store.NewTenantDomainRepo(db),
		credRepo:   store.NewCredentialRepo(db),
		db:         db,
	}

	if err := m.RefreshTenantMap(ctx); err != nil {
		return nil, fmt.Errorf("user tenant map: %w", err)
	}

	slog.Info("user module initialized")
	return m, nil
}

func (m *Module) DB() *gorm.DB                    { return m.db }
func (m *Module) UserRepo() *store.UserRepo           { return m.userRepo }
func (m *Module) TenantRepo() *store.TenantRepo       { return m.tenantRepo }
func (m *Module) DomainRepo() *store.TenantDomainRepo { return m.domainRepo }
func (m *Module) CredentialRepo() *store.CredentialRepo { return m.credRepo }
func (m *Module) DomainTrie() *DomainTrie              { return m.tenants }

func (m *Module) ResolveTenant(hostname string) (*TenantInfo, bool) {
	if m.tenants == nil {
		return nil, false
	}
	return m.tenants.Resolve(hostname)
}

func (m *Module) RefreshTenantMap(ctx context.Context) error {
	domains, err := m.domainRepo.ListAllWithTenant(ctx)
	if err != nil {
		return err
	}
	entries := make([]DomainEntry, len(domains))
	for i, d := range domains {
		entries[i] = DomainEntry{
			Pattern:    d.Pattern,
			TenantCode: d.TenantCode,
			TenantUUID: d.TenantUUID,
			IsWildcard: d.IsWildcard,
		}
	}
	m.tenants.Replace(entries)
	slog.Info("tenant domain trie refreshed", "count", len(entries))
	return nil
}

func (m *Module) AdminHandler() http.Handler {
	return m.adminRoutes()
}

func (m *Module) SetRBACDeps(roleRepo *rbacstore.RoleRepo) {
	m.rbacRoleRepo = roleRepo
}

func (m *Module) SetAdminPath(path string) {
	m.adminPath = path
}

func (m *Module) adminRoutes() http.Handler {
	mux := http.NewServeMux()

	pgCfg := handler.PaginationConfig{
		DefaultPageSize: m.cfg.Pagination.DefaultPageSize,
		MaxPageSize:     m.cfg.Pagination.MaxPageSize,
	}

	onChange := func() {
		m.RefreshTenantMap(context.Background())
	}

	th := handler.NewTenantHandler(m.tenantRepo, pgCfg, onChange, m.db, m.adminPath)
	dh := handler.NewTenantDomainHandler(m.domainRepo, m.tenantRepo, onChange)
	uh := handler.NewUserHandler(m.userRepo, m.credRepo, m.tenantRepo, pgCfg)

	mux.HandleFunc("GET /tenants", th.List)
	mux.HandleFunc("POST /tenants", th.Create)
	mux.HandleFunc("GET /tenants/{id}", th.Get)
	mux.HandleFunc("PUT /tenants/{id}", th.Update)
	mux.HandleFunc("DELETE /tenants/{id}", th.Delete)

	mux.HandleFunc("GET /tenants/{id}/domains", dh.List)
	mux.HandleFunc("POST /tenants/{id}/domains", dh.Create)
	mux.HandleFunc("DELETE /tenants/{id}/domains/{domainId}", dh.Delete)

	// Tenant admin provisioning (requires RBAC role repo)
	if m.rbacRoleRepo != nil {
		ah := handler.NewTenantAdminHandler(m.userRepo, m.credRepo, m.tenantRepo, m.rbacRoleRepo, m.db, m.adminPath)
		mux.HandleFunc("POST /tenants/{id}/admins", ah.Create)
	}

	mux.HandleFunc("GET /users", uh.List)
	mux.HandleFunc("POST /users", uh.Create)
	mux.HandleFunc("GET /users/{id}", uh.Get)
	mux.HandleFunc("PUT /users/{id}", uh.Update)
	mux.HandleFunc("DELETE /users/{id}", uh.Delete)

	mux.HandleFunc("GET /users/{id}/credentials", uh.ListCredentials)
	mux.HandleFunc("POST /users/{id}/credentials", uh.CreateCredential)
	mux.HandleFunc("DELETE /users/{id}/credentials/{credId}", uh.DeleteCredential)

	return mux
}
