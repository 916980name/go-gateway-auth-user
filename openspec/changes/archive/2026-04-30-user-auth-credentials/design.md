## Context

The gateway is a reverse-proxy that currently delegates authentication entirely to upstream backends. After the upstream confirms identity (via its own login endpoint), the gateway reads the response body, signs a JWT, and manages online-session state. Authorization is handled by a Casbin-based RBAC module (`pkg/rbac/`) that also owns user, tenant, and tenant-domain entities.

This design introduces gateway-mode direct authentication alongside the existing upstream delegation, and restructures the codebase so that user/tenant entities live in their own module (`pkg/user/`), independent of both auth and RBAC.

Key constraints:
- Existing upstream-mode sites must continue working unchanged
- The same gateway instance may serve both upstream-mode and gateway-mode sites
- JWT signing, online-cache, and refresh-token infrastructure already work and should be reused
- PostgreSQL is the only relational store; Redis is used for caching

## Goals / Non-Goals

**Goals:**
- Extract user/tenant entities into `pkg/user/` with clean dependency boundaries
- Implement `user_credentials` table and pluggable credential provider interface
- Deliver a working password-based gateway-mode login flow
- Site-level configuration to choose auth mode (upstream vs gateway)
- Maintain backward compatibility for upstream-mode sites

**Non-Goals:**
- SMS provider implementation (table and interface ready, provider deferred)
- OAuth provider implementation (table and interface ready, provider deferred)
- User self-registration flow (admin creates users for now)
- Password reset / forgot-password flow
- Token format changes (JWT payload structure stays the same)

## Decisions

### 1. User-tenant relationship: tenant-scoped users (model B)

Each `users` row has a `tenant_id` FK. A user belongs to exactly one tenant. The `tenant_users` join table is removed.

**Why over model A (global users joining multiple tenants):**
- Simpler mental model: username/email/phone uniqueness is naturally tenant-scoped
- No ambiguity about which tenant a credential belongs to
- Matches the domain-based tenant resolution: one domain → one tenant → user namespace

**Trade-off:** A person who needs access to multiple tenants must have separate user accounts. Acceptable for this system's use case.

### 2. Module structure: `pkg/user/` as the foundation layer

```
pkg/user/   ← owns users, tenants, tenant_domains, user_credentials, domain_trie
pkg/auth/   ← owns authentication logic, credential providers
pkg/rbac/   ← owns roles, permissions, enforcement (references user/store)
```

**Why not keep users in RBAC:**
- Authentication is more fundamental than authorization; the dependency should flow auth → user, rbac → user, not auth → rbac
- RBAC becomes cleaner: only roles, permissions, and policy enforcement

**Why not merge credentials into user/store:**
- `user_credentials` lives in `pkg/user/store/` (it's a data entity)
- Authentication *logic* (bcrypt, provider dispatch) lives in `pkg/auth/` (it's behavior)
- Clean separation: `pkg/user/` is CRUD, `pkg/auth/` is verification

### 3. Credential table design

```sql
user_credentials (
  id, user_id, tenant_id, provider_type,
  credential, identifier, metadata, status,
  created_at, updated_at
)
```

- `credential`: bcrypt hash for password provider, NULL for SMS/OAuth
- `identifier`: NULL for password/SMS (lookup goes through `users` table), external user ID for OAuth
- `UNIQUE(user_id, tenant_id, provider_type)`: one credential record per provider per user per tenant
- Partial unique index on `(tenant_id, provider_type, identifier) WHERE identifier IS NOT NULL`: for OAuth reverse-lookup
- `tenant_id` is denormalized from `users.tenant_id` for query efficiency and FK integrity

### 4. CredentialProvider interface

```go
type AuthRequest struct {
    TenantID   int64
    Provider   string  // "password", "sms", "oauth:github"
    Identifier string  // username/email/phone or OAuth code
    Credential string  // password or SMS code
}

type AuthResult struct {
    UserID   int64
    Username string
    TenantID int64
}

type CredentialProvider interface {
    Type() string
    Authenticate(ctx context.Context, req AuthRequest) (*AuthResult, error)
}
```

Providers are registered in a `map[string]CredentialProvider`. The login handler dispatches by the `provider` field in the request body.

**Password provider flow:**
1. Infer identifier type: contains `@` → email, digits/`+` → phone, else → username
2. Query `users` WHERE `(username|email|phone) = ? AND tenant_id = ? AND status = 1`
3. Query `user_credentials` WHERE `user_id = ? AND tenant_id = ? AND provider_type = 'password' AND status = 1`
4. `bcrypt.CompareHashAndPassword(credential, input)`
5. Return `AuthResult`

### 5. Site-level auth mode configuration

```yaml
sites:
  - hostname: app.example.com
    auth:
      mode: upstream          # existing behavior via LoginFilter
    inOutFilter:
      loginPath: ["/login"]
      ...

  - hostname: portal.example.com
    auth:
      mode: gateway           # new direct authentication
      loginPath: "/auth/login"
      logoutPath: "/auth/logout"
      providers:
        - type: password
```

When `mode: gateway`, the login/logout paths are handled by `pkg/auth/` handlers directly (not proxied to upstream). When `mode: upstream`, existing `LoginFilter`/`LogoutFilter` middleware works unchanged.

### 6. Gateway login handler is not a middleware

Upstream-mode uses proxy middleware (request → upstream → post-process response). Gateway-mode login has no upstream to proxy to — it's a direct HTTP handler that:
1. Parses request body
2. Calls the appropriate CredentialProvider
3. Signs JWT using existing `pkg/jwt/` + `pkg/middleware/common.go` token generation functions
4. Writes OnlineCache
5. Returns tokens in response

The existing `generateAccessToken` / `generateTwoTokens` functions in `pkg/middleware/common.go` are reusable. They take `bodyBytes` (JSON user info) and return signed tokens. The auth handler constructs the same JSON payload from `AuthResult` and calls these functions.

### 7. Database connection strategy

`pkg/user/` creates its own `*gorm.DB` connection. `pkg/rbac/` keeps its own. Both connect to the same PostgreSQL database but maintain separate connection pools. This matches the "independent" requirement and allows future separation if needed.

Migration execution order: `user` module runs first (owns `users`, `tenants` tables), then `rbac` module runs (owns `roles`, `permissions` with FKs to `users`).

### 8. users table unique constraints

```sql
-- Replace global UNIQUE(username) with:
UNIQUE(tenant_id, username)
-- Conditional indexes for nullable fields:
CREATE UNIQUE INDEX ON users(tenant_id, email) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX ON users(tenant_id, phone) WHERE phone IS NOT NULL;
```

Application-level validation: when creating/updating a user's email or phone, check no other active user in the same tenant has the same value.

## Risks / Trade-offs

**[Migration complexity]** → Adding `tenant_id` to `users` requires backfilling from `tenant_users`. If a user belongs to multiple tenants in current data, the migration must pick one (LIMIT 1) or fail.
→ Mitigation: The system is early-stage; verify current data has 1:1 user-tenant mappings before migrating. Add a pre-migration check.

**[Split migrations across modules]** → Two modules running independent migrations against shared tables could cause ordering issues.
→ Mitigation: `gateway.go` initializes `user.New()` before `rbac.New()`, guaranteeing order. Document this constraint.

**[RBAC FK to users table]** → `user_roles.user_id` references `users(id)`. After the split, RBAC's migration creates this FK but doesn't own the referenced table.
→ Mitigation: RBAC migration runs second. The FK target already exists. This is a standard cross-schema FK pattern.

**[Reusing token generation functions]** → `generateAccessToken` in `pkg/middleware/common.go` is package-private and tightly coupled to the proxy response flow.
→ Mitigation: Extract token generation into a shared function or make it accessible to `pkg/auth/`. May require moving to `pkg/jwt/` or creating a thin wrapper.

**[Password in gateway memory]** → The gateway process now handles raw passwords (briefly, for bcrypt comparison).
→ Mitigation: Standard practice for any auth service. Passwords are never logged, never stored in plaintext, zeroed after use where practical.
