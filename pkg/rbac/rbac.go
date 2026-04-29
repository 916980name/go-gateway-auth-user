package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"api-gateway/pkg/rbac/store"
)

type RBAC struct {
	cfg        Config
	enforcer   *Enforcer
	tenants    *DomainTrie
	tenantRepo *store.TenantRepo
	domainRepo *store.TenantDomainRepo
	userRepo   *store.UserRepo
	roleRepo   *store.RoleRepo
	permRepo   *store.PermissionRepo
}

func New(ctx context.Context, cfg Config) (*RBAC, error) {
	cfg.ApplyDefaults()

	dbCfg := store.DBConfig{
		DSN:                    cfg.DB.DSN,
		MaxOpenConns:           cfg.DB.MaxOpenConns,
		MaxIdleConns:           cfg.DB.MaxIdleConns,
		ConnMaxLifetimeMinutes: cfg.DB.ConnMaxLifetimeMinutes,
	}
	db, err := store.NewDB(ctx, dbCfg)
	if err != nil {
		return nil, fmt.Errorf("rbac db: %w", err)
	}

	slog.Info("running RBAC database migrations")
	if err := store.RunMigrations(cfg.DB.DSN); err != nil {
		return nil, fmt.Errorf("rbac migrations: %w", err)
	}

	slog.Info("seeding RBAC bootstrap data")
	if err := store.Seed(ctx, db, cfg.SuperAdmin.Username); err != nil {
		return nil, fmt.Errorf("rbac seed: %w", err)
	}

	slog.Info("initializing Casbin enforcer")
	enforcer, err := NewEnforcer(cfg.DB.DSN)
	if err != nil {
		return nil, fmt.Errorf("rbac enforcer: %w", err)
	}

	rc := &RBAC{
		cfg:        cfg,
		enforcer:   enforcer,
		tenants:    NewDomainTrie(),
		tenantRepo: store.NewTenantRepo(db),
		domainRepo: store.NewTenantDomainRepo(db),
		userRepo:   store.NewUserRepo(db),
		roleRepo:   store.NewRoleRepo(db),
		permRepo:   store.NewPermissionRepo(db),
	}

	if err := rc.RefreshTenantMap(ctx); err != nil {
		return nil, fmt.Errorf("rbac tenant map: %w", err)
	}

	slog.Info("RBAC module initialized", "adminPath", cfg.AdminPath)
	return rc, nil
}

func (rc *RBAC) Enforce(sub, dom, obj, act string) (bool, error) {
	return rc.enforcer.Enforce(sub, dom, obj, act)
}

func (rc *RBAC) ReloadPolicy() error {
	return rc.enforcer.LoadPolicy()
}

func (rc *RBAC) AdminHandler() http.Handler {
	return rc.adminRoutes()
}

func (rc *RBAC) autoProvisionUser(ctx context.Context, username, email, phone string) {
	u := &store.User{
		Username: username,
		Email:    email,
		Phone:    phone,
	}
	if err := rc.userRepo.Upsert(ctx, u); err != nil {
		slog.Error("auto-provision user failed", "error", err, "username", username)
	}
}
