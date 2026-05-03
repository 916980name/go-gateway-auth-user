package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"api-gateway/pkg/rbac/store"
	"api-gateway/pkg/user"
	userstore "api-gateway/pkg/user/store"

	"gorm.io/gorm"
)

type RBAC struct {
	cfg        Config
	enforcer   *Enforcer
	userMod    *user.Module
	roleRepo   *store.RoleRepo
	permRepo   *store.PermissionRepo
	policySync *store.PolicySync
}

func New(ctx context.Context, cfg Config, dsn string, schema string, db *gorm.DB, userMod *user.Module) (*RBAC, error) {
	cfg.ApplyDefaults()

	slog.Info("initializing Casbin enforcer")
	enforcer, err := NewEnforcer(dsn, schema)
	if err != nil {
		return nil, fmt.Errorf("rbac enforcer: %w", err)
	}

	rc := &RBAC{
		cfg:        cfg,
		enforcer:   enforcer,
		userMod:    userMod,
		roleRepo:   store.NewRoleRepo(db),
		permRepo:   store.NewPermissionRepo(db),
		policySync: store.NewPolicySync(db),
	}

	if err := rc.SyncPolicies(ctx); err != nil {
		return nil, fmt.Errorf("initial policy sync: %w", err)
	}

	slog.Info("RBAC module initialized", "adminPath", cfg.AdminPath)
	return rc, nil
}

func (rc *RBAC) Enforce(sub, dom, obj, act string) (bool, error) {
	return rc.enforcer.Enforce(sub, dom, obj, act)
}

func (rc *RBAC) SyncPolicies(ctx context.Context) error {
	grouping, err := rc.policySync.QueryGroupingPolicies(ctx)
	if err != nil {
		slog.Error("query grouping policies failed", "error", err)
		return err
	}
	policies, err := rc.policySync.QueryPolicies(ctx)
	if err != nil {
		slog.Error("query policies failed", "error", err)
		return err
	}
	return rc.enforcer.RebuildPolicies(grouping, policies)
}

func (rc *RBAC) ReloadPolicy() error {
	return rc.SyncPolicies(context.Background())
}

func (rc *RBAC) AdminHandler() http.Handler {
	return rc.adminRoutes()
}

func (rc *RBAC) resolveTenant(hostname string) (string, bool) {
	if rc.userMod == nil {
		return "", false
	}
	return rc.userMod.ResolveTenant(hostname)
}

func (rc *RBAC) autoProvisionUser(ctx context.Context, tenantCode, username, email, phone string) {
	if rc.userMod == nil {
		return
	}
	tenant, err := rc.userMod.TenantRepo().GetByCode(ctx, tenantCode)
	if err != nil {
		slog.Error("auto-provision: tenant lookup failed", "error", err, "tenantCode", tenantCode)
		return
	}
	u := &userstore.User{
		TenantID: tenant.ID,
		Username: username,
		Email:    email,
		Phone:    phone,
	}
	if err := rc.userMod.UserRepo().Upsert(ctx, u); err != nil {
		slog.Error("auto-provision user failed", "error", err, "username", username)
	}
}
