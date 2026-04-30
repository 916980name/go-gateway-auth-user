## 1. Create pkg/user module scaffold

- [x] 1.1 Create `pkg/user/` directory structure: `store/`, `store/migrations/`, `handler/`
- [x] 1.2 Create `pkg/user/store/db.go` — DB connection setup (copy from `pkg/rbac/store/db.go`, shared pattern)
- [x] 1.3 Create `pkg/user/store/models.go` — Move `User` (add TenantID field), `Tenant`, `TenantDomain` structs from `pkg/rbac/store/models.go`; add `UserCredential` model; keep shared `PaginationParams`/`PaginatedResult`/`Pagination`
- [x] 1.4 Create `pkg/user/config.go` — Config struct for user module (DB config, pagination defaults)

## 2. Database migrations

- [x] 2.1 Create `pkg/user/store/migrations/001_init_schema.up.sql` — users (with tenant_id), tenants, tenant_domains tables (extracted from rbac migration)
- [x] 2.2 Create `pkg/user/store/migrations/001_init_schema.down.sql`
- [x] 2.3 Create `pkg/user/store/migrations/002_user_credentials.up.sql` — user_credentials table with constraints and indexes
- [x] 2.4 Create `pkg/user/store/migrations/002_user_credentials.down.sql`
- [x] 2.5 Create `pkg/user/store/migrate.go` — Migration runner using golang-migrate
- [x] 2.6 Update `pkg/rbac/store/migrations/001_init_schema.up.sql` — Remove users, tenants, tenant_domains, tenant_users tables; keep only roles, permissions, user_roles, role_permissions (with FK references to users)
- [x] 2.7 Update `pkg/rbac/store/migrations/001_init_schema.down.sql` — Match the updated up migration

## 3. User module repos

- [x] 3.1 Create `pkg/user/store/user_repo.go` — Move from `pkg/rbac/store/user_repo.go`; add tenant_id scoping to all queries; remove ListTenants/AddToTenant/RemoveFromTenant; add `FindByIdentifier(ctx, tenantID, identifier)` for login lookup (username/email/phone)
- [x] 3.2 Create `pkg/user/store/tenant_repo.go` — Move from `pkg/rbac/store/tenant_repo.go`
- [x] 3.3 Create `pkg/user/store/tenant_domain_repo.go` — Move from `pkg/rbac/store/tenant_domain_repo.go`
- [x] 3.4 Create `pkg/user/store/credential_repo.go` — CRUD for user_credentials (Create, GetByUserAndProvider, ListByUser, SoftDelete)
- [x] 3.5 Create `pkg/user/store/seed.go` — Seed __system__ tenant and super admin user (moved from rbac seed)

## 4. User module handlers and initialization

- [x] 4.1 Create `pkg/user/handler/response.go` — Copy shared response helpers from `pkg/rbac/handler/response.go`
- [x] 4.2 Create `pkg/user/handler/user_handler.go` — Move from `pkg/rbac/handler/user_handler.go`; remove tenant_users endpoints; add tenant_id to create request; add credential management endpoints
- [x] 4.3 Create `pkg/user/handler/tenant_handler.go` — Move from `pkg/rbac/handler/tenant_handler.go`
- [x] 4.4 Create `pkg/user/handler/tenant_domain_handler.go` — Move from `pkg/rbac/handler/tenant_domain_handler.go`
- [x] 4.5 Move `pkg/rbac/domain_trie.go` and `pkg/rbac/domain_trie_test.go` to `pkg/user/`
- [x] 4.6 Create `pkg/user/user.go` — Main struct with `New(ctx, cfg)`, admin route registration, expose store repos

## 5. Refactor pkg/rbac to depend on pkg/user

- [x] 5.1 Update `pkg/rbac/store/models.go` — Remove User, Tenant, TenantDomain, TenantUser structs; keep Role, Permission, UserRole, RolePermission
- [x] 5.2 Delete `pkg/rbac/store/user_repo.go`, `pkg/rbac/store/tenant_repo.go`, `pkg/rbac/store/tenant_domain_repo.go` from rbac
- [x] 5.3 Delete `pkg/rbac/handler/user_handler.go`, `pkg/rbac/handler/tenant_handler.go`, `pkg/rbac/handler/tenant_domain_handler.go` from rbac
- [x] 5.4 Delete `pkg/rbac/domain_trie.go` and `pkg/rbac/domain_trie_test.go` from rbac
- [x] 5.5 Update `pkg/rbac/rbac.go` — Change `New()` signature to accept `*user.Module`; remove internal repo creation for user/tenant/domain entities
- [x] 5.6 Update `pkg/rbac/admin.go` — Remove user/tenant/domain admin routes (now served by pkg/user); keep only role/permission routes
- [x] 5.7 Update `pkg/rbac/store/seed.go` — Simplify to only seed system_admin role + assignment; assume __system__ tenant and super admin user already exist
- [x] 5.8 Update `pkg/rbac/middleware.go` — Adjust tenant resolution to use user module's domain trie via `*user.Module`

## 6. Create pkg/auth module

- [x] 6.1 Create `pkg/auth/config.go` — Auth module config (providers list)
- [x] 6.2 Create `pkg/auth/provider.go` — `CredentialProvider` interface, `AuthRequest`, `AuthResult` types, error sentinels
- [x] 6.3 Create `pkg/auth/provider_password.go` — Password provider: user lookup via user repo, bcrypt verification
- [x] 6.4 Create `pkg/auth/handler/login_handler.go` — POST login handler: parse request, resolve tenant, dispatch to provider, JWT generation, set headers/cookies
- [x] 6.5 Create `pkg/auth/handler/logout_handler.go` — POST logout handler: extract JWT, verify, remove from OnlineCache, expire cookies
- [x] 6.6 Create `pkg/auth/auth.go` — Main struct with `New(cfg, userMod)`, provider registration, Authenticate dispatch

## 7. Update gateway config and route wiring

- [x] 7.1 Update `pkg/config/config.go` — Add `SiteAuthConfig` struct to `Site` with mode, loginPath, logoutPath, providers fields; add `User *user.Config` to main Config
- [x] 7.2 Update `internal/api-gateway/gateway.go` — Initialize user module first, then pass to auth and rbac modules; merge admin handlers
- [x] 7.3 Update `internal/api-gateway/route.go` — For sites with `auth.mode: gateway`, register auth handler login/logout endpoints; upstream mode unchanged
- [x] 7.4 Auth handler uses `pkg/jwt.GenerateJWTRSA` directly — no extraction needed from middleware

## 8. Tests

- [x] 8.1 Write unit tests for `pkg/user/store/` repos — identifier type inference, isAllDigits
- [x] 8.2 Write unit tests for `pkg/auth/` — Module.Authenticate dispatch, provider registration, error propagation
- [x] 8.3 Write unit tests for `pkg/auth/handler/` — method validation, input parsing, missing fields, unknown domain, logout token extraction
- [x] 8.4 Update existing `pkg/rbac/` tests — Fixed middleware_test.go (removed DomainTrie), models_test.go (removed User type)
- [ ] 8.5 Write integration test for gateway-mode login flow — end-to-end (requires running PostgreSQL)
