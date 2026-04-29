## 1. Configuration & Dependencies

- [x] 1.1 Add new Go dependencies: casbin/v2, casbin-pg-adapter, pgx/v5, golang-migrate/v4
- [x] 1.2 Create `pkg/rbac/config.go` — self-contained `rbac.Config` struct (DB settings, admin path, super admin, pagination defaults) with no gateway imports
- [x] 1.3 Add `RBACConfig` field to gateway's `pkg/config/config.go` that maps to `rbac.Config`, wire Viper parsing
- [x] 1.4 Add `rbac` section to config template `configs/api-gateway.yaml.template`

## 2. Database Layer

- [x] 2.1 Create `pkg/rbac/store/db.go` — PostgreSQL connection pool setup using pgx/v5, accepts `rbac.Config` directly
- [x] 2.2 Create migration file `pkg/rbac/store/migrations/001_init_schema.up.sql` with all tables, constraints, and indexes
- [x] 2.3 Create migration file `pkg/rbac/store/migrations/001_init_schema.down.sql` for rollback
- [x] 2.4 Add migration runner to `pkg/rbac/store/db.go` using golang-migrate with embedded SQL files
- [x] 2.5 Create `pkg/rbac/store/models.go` — DB model structs (User, Tenant, Role, Permission, TenantUser, UserRole, RolePermission)
- [x] 2.6 Add bootstrap seed logic — create `__system__` tenant, `system_admin` role, super admin user, and role assignment on first init

## 3. Repository Layer

- [x] 3.1 Create `pkg/rbac/store/tenant_repo.go` — Tenant CRUD (create, get by UUID, list paginated, update, soft delete)
- [x] 3.2 Create `pkg/rbac/store/user_repo.go` — User CRUD (create, get by UUID, get by username, list paginated with search, update, soft delete, upsert for auto-provisioning)
- [x] 3.3 Create `pkg/rbac/store/role_repo.go` — Role CRUD (create, get by UUID, list by tenant paginated, update, delete with cascade cleanup)
- [x] 3.4 Create `pkg/rbac/store/permission_repo.go` — Permission CRUD (create, get by UUID, list by tenant paginated, update, delete with cascade cleanup)
- [x] 3.5 Add tenant-user association methods to user_repo (list user's tenants, add to tenant, remove from tenant)
- [x] 3.6 Add user-role assignment methods to role_repo (get user's roles in tenant, set user's roles with full replace)
- [x] 3.7 Add role-permission assignment methods to permission_repo (get role's permissions, set role's permissions with full replace)

## 4. Casbin Engine

- [x] 4.1 Create `pkg/rbac/model.go` — Embedded Casbin model string (RBAC with domains, keyMatch2)
- [x] 4.2 Create `pkg/rbac/enforcer.go` — Casbin enforcer initialization with pg-adapter, LoadPolicy, and Enforce wrapper

## 5. RBAC Core (standalone module)

- [x] 5.1 Create `pkg/rbac/rbac.go` — Module entry point: `New(cfg Config) (*RBAC, error)` that initializes DB, runs migrations, sets up Casbin, loads tenant map. Returns a struct exposing `Enforce()`, `Middleware()`, and `AdminHandler()`
- [x] 5.2 Create `pkg/rbac/middleware.go` — `http.Handler`-based middleware (extract user from context, resolve hostname → tenant, enforce via Casbin). Uses standard context keys, no gateway imports
- [x] 5.3 Add hostname-to-tenant in-memory map with load-from-DB and refresh methods
- [x] 5.4 Add user auto-provisioning logic in middleware (upsert on first encounter)
- [x] 5.5 Define context key contracts in `pkg/rbac/context.go` — document which context keys the middleware reads (username, email, phone set by caller) and writes

## 6. Admin API Handlers (inside pkg/rbac/)

- [x] 6.1 Create `pkg/rbac/handler/response.go` — Pagination struct, error response helpers, page param parsing
- [x] 6.2 Create `pkg/rbac/handler/tenant_handler.go` — Handlers for tenant CRUD (list, create, get, update, delete)
- [x] 6.3 Create `pkg/rbac/handler/user_handler.go` — Handlers for user CRUD and user-tenant association (list, create, get, update, delete, list tenants, add/remove tenant)
- [x] 6.4 Create `pkg/rbac/handler/role_handler.go` — Handlers for role CRUD, role permissions (list, create, update, delete, get permissions, set permissions)
- [x] 6.5 Create `pkg/rbac/handler/permission_handler.go` — Handlers for permission CRUD (list, create, update, delete)
- [x] 6.6 Create `pkg/rbac/admin.go` — Admin route registration using standard `http.ServeMux` or lightweight internal router, returns `http.Handler`

## 7. Gateway Adapter & Integration

- [x] 7.1 Create `internal/api-gateway/rbac_adapter.go` — Thin adapter: converts `rbac.Middleware()` (http.Handler) to gateway's `proxy.Middleware` pattern; maps gateway context keys (user info from AuthFilter) to RBAC context keys
- [x] 7.2 Modify `internal/api-gateway/gateway.go` — Conditional RBAC initialization: read gateway config, construct `rbac.Config`, call `rbac.New()`, mount admin handler on mux router
- [x] 7.3 Modify `internal/api-gateway/route.go` — Inject adapted RBACFilter into middleware chain when RBAC is enabled; pass `rbacEnabled` flag to `AuthFilter`
- [x] 7.4 Modify `pkg/middleware/authFilter.go` — Add `rbacEnabled` parameter to skip `checkPrivileges()` when RBAC is active

## 8. Testing

- [x] 8.1 Unit tests for `pkg/rbac/store/` repositories (mock or test DB)
- [x] 8.2 Unit tests for `pkg/rbac/handler/` — request parsing, validation, response format
- [x] 8.3 Unit tests for RBAC middleware — allow/deny scenarios, hostname resolution, auto-provisioning
- [x] 8.4 Unit tests for Casbin model correctness — policy matching, role inheritance, domain isolation
- [x] 8.5 Unit tests for `AuthFilter` modification — verify JWT-only mode when rbacEnabled=true, full mode when false
- [x] 8.6 Integration test: full workflow (create tenant → role → permission → assign → enforce)
- [x] 8.7 Test toggle behavior: RBAC on vs off, verify no regression in existing auth flow
- [x] 8.8 Verify `pkg/rbac/` has zero imports from gateway packages (go vet / import check)
