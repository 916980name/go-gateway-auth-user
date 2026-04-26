# RBAC Permission Module Design

## Overview

Enhance the existing Go API gateway into a **permission gateway** with a complete, independent RBAC (Role-Based Access Control) module. The module is built on **Casbin** with **PostgreSQL** storage, supports **multi-tenant** (multi-domain/business) isolation, and can be toggled on/off via configuration.

When disabled, the gateway falls back to its existing simple privilege matching logic with zero impact.

### Goals

- Complete RBAC with multi-tenant isolation: users are global, permissions are per-tenant
- Data model designed toward a unified authentication center — one user identity across multiple business domains with different roles/permissions per domain
- Casbin as the policy engine with PostgreSQL adapter for persistence
- REST management API for dynamic CRUD of tenants, users, roles, and permissions
- Feature toggle: `rbac.enabled` in config — off means no DB connection, no Casbin, no admin routes
- All list/query APIs use pagination

### Non-Goals

- ABAC or resource-level data scope control
- User registration/password management (users come from backend login service)
- Frontend admin UI (API only)
- Multi-instance policy sync via Redis Pub/Sub (future extension)

---

## Data Model

### Principle

**Users are global. Permissions are tenant-scoped.** A single user can belong to multiple tenants with different roles in each.

### Database Schema

Uses `BIGSERIAL` auto-increment as primary key (better B-tree performance, smaller index size, faster FK joins). UUID as external business identifier (prevents ID enumeration, safe for API exposure). All foreign keys reference the integer `id`. All API responses expose only the `uuid`.

```sql
-- Global layer

CREATE TABLE users (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    username    VARCHAR(128) NOT NULL UNIQUE,
    display_name VARCHAR(256),
    email       VARCHAR(256),
    phone       VARCHAR(32),
    status      SMALLINT NOT NULL DEFAULT 1,  -- 1=active, 0=disabled
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tenants (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    code        VARCHAR(64) NOT NULL UNIQUE,   -- e.g. "site-a"
    name        VARCHAR(256) NOT NULL,
    hostname    VARCHAR(256) NOT NULL UNIQUE,   -- maps to sites[].hostname in config
    status      SMALLINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tenant-scoped layer

CREATE TABLE tenant_users (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    status      SMALLINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, tenant_id)
);

CREATE TABLE roles (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code        VARCHAR(64) NOT NULL,          -- e.g. "admin", "viewer"
    name        VARCHAR(256) NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, code)
);

CREATE TABLE permissions (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code        VARCHAR(128) NOT NULL,         -- e.g. "user:read"
    name        VARCHAR(256) NOT NULL,
    resource    VARCHAR(512) NOT NULL,         -- route path, e.g. "/api/users/*"
    action      VARCHAR(32) NOT NULL,          -- HTTP method: GET, POST, PUT, DELETE, *
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, code)
);

CREATE TABLE user_roles (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id     BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(user_id, role_id, tenant_id)
);

CREATE TABLE role_permissions (
    id              BIGSERIAL PRIMARY KEY,
    role_id         BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id   BIGINT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(role_id, permission_id)
);
```

### Entity Relationships

```
users (global)
  └── tenant_users ──► tenants (business domains, mapped to site hostnames)
  └── user_roles ──► roles (tenant-scoped)
                       └── role_permissions ──► permissions (tenant-scoped)
                                                  ├── resource (route path)
                                                  └── action (HTTP method)
```

### Indexes

```sql
CREATE INDEX idx_tenant_users_user_id ON tenant_users(user_id);
CREATE INDEX idx_tenant_users_tenant_id ON tenant_users(tenant_id);
CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);
CREATE INDEX idx_permissions_tenant_id ON permissions(tenant_id);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_tenant_id ON user_roles(tenant_id);
CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
```

### API ID Convention

All API path parameters (`:id`, `:tenantId`, `:userId`) use **UUID** values, not integer IDs. Internally the system resolves UUID → integer ID for database operations. Integer IDs are never exposed externally.

---

## Casbin Integration

### Model Definition (RBAC with Domains)

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && keyMatch2(r.obj, p.obj) && r.act == p.act
```

- `sub` — user identifier (username)
- `dom` — tenant code (maps to hostname)
- `obj` — resource path (e.g. `/api/users/:id`), uses `keyMatch2` for path parameter matching
- `act` — HTTP method (GET, POST, PUT, DELETE)

### Policy Examples

```
# Role assignment: alice has "admin" role in tenant "site-a"
g, alice, admin, site-a

# Permission policies: admin in site-a can GET and POST /api/users/*
p, admin, site-a, /api/users/*, GET
p, admin, site-a, /api/users/*, POST

# alice has only "viewer" role in site-b
g, alice, viewer, site-b
p, viewer, site-b, /api/users/*, GET
```

### Policy Sync

- **Startup**: Load all policies from PostgreSQL via Casbin's pg-adapter into the in-memory engine
- **On management API changes**: After DB write, call `enforcer.LoadPolicy()` to reload
- **Multi-instance sync**: Future extension via Redis Pub/Sub (not in initial scope)

---

## Middleware Architecture

### Request Flow

```
Request arrives
    │
    ▼
RequestFilter (existing: extract IP, domain, method, URI)
    │
    ▼
RateLimiter by IP (existing, if configured)
    │
    ▼
AuthFilter (modified: JWT verification only when RBAC enabled)
    │
    ▼
RBACFilter (NEW, injected only when rbac.enabled == true)
    │  1. Extract username from context (set by AuthFilter)
    │  2. Resolve hostname → tenant code
    │  3. Extract resource path and HTTP method
    │  4. Call casbin.Enforce(username, tenantCode, path, method)
    │  5. Allow → continue | Deny → 403 Forbidden
    │
    ▼
RateLimiter by User (existing, if configured)
    │
    ▼
Backend Proxy (existing)
```

### AuthFilter Modification

The existing `AuthFilter` combines JWT verification and privilege matching. When RBAC is enabled:

- `AuthFilter` performs **JWT verification only** — extract user info, set context, validate token
- Privilege matching logic is **skipped** (handled by `RBACFilter`)

When RBAC is disabled:

- `AuthFilter` works exactly as before — JWT verification + privilege matching from route config

This is achieved by splitting the current `AuthFilter` and making privilege matching conditional.

### User Auto-Provisioning

When RBAC is enabled, the `RBACFilter` auto-creates a user record in the `users` table on first encounter:

1. After `AuthFilter` extracts user info from JWT and sets it in context
2. `RBACFilter` checks if the username exists in the `users` table
3. If not, creates a new record using info from the JWT (`username`, `email`, `phone` if available)
4. This is a lightweight upsert — no performance concern since it's cached after first lookup

This ensures users who authenticate through the backend login service automatically get RBAC user records without manual admin intervention. Role assignment still requires explicit admin action via the management API.

### Hostname-to-Tenant Resolution

The `RBACFilter` resolves the request hostname to a tenant code:

1. Request hostname is already available in context (set by `RequestFilter`)
2. Maintain an in-memory map of `hostname → tenant_code` (loaded from DB at startup, refreshed on tenant CRUD)
3. If hostname not found in map → 403 (unknown domain)

---

## Management REST API

All list endpoints use offset pagination with configurable page size (default 20, max 100).

### Common Response Structures

```json
// Paginated list response
{
  "data": [...],
  "pagination": {
    "page": 1,
    "pageSize": 20,
    "total": 150
  }
}

// Error response
{
  "error": {
    "code": "INVALID_INPUT",
    "message": "role code is required"
  }
}
```

### Tenant Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/tenants` | List all tenants (paginated) |
| POST | `/admin/tenants` | Create tenant |
| GET | `/admin/tenants/:id` | Get tenant detail |
| PUT | `/admin/tenants/:id` | Update tenant |
| DELETE | `/admin/tenants/:id` | Delete tenant (soft delete) |

### User Management

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/users` | List users (paginated, searchable) |
| POST | `/admin/users` | Create user |
| GET | `/admin/users/:id` | Get user detail |
| PUT | `/admin/users/:id` | Update user |
| DELETE | `/admin/users/:id` | Disable user (soft delete) |
| GET | `/admin/users/:id/tenants` | List user's tenants (paginated) |
| POST | `/admin/users/:id/tenants/:tenantId` | Add user to tenant |
| DELETE | `/admin/users/:id/tenants/:tenantId` | Remove user from tenant |

### Role Management (Tenant-Scoped)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/tenants/:tenantId/roles` | List roles (paginated) |
| POST | `/admin/tenants/:tenantId/roles` | Create role |
| PUT | `/admin/tenants/:tenantId/roles/:id` | Update role |
| DELETE | `/admin/tenants/:tenantId/roles/:id` | Delete role |
| GET | `/admin/tenants/:tenantId/roles/:id/permissions` | Get role's permissions (paginated) |
| PUT | `/admin/tenants/:tenantId/roles/:id/permissions` | Set role's permissions (full replace) |

### User Role Assignment (Tenant-Scoped)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/tenants/:tenantId/users/:userId/roles` | Get user's roles in tenant (paginated) |
| PUT | `/admin/tenants/:tenantId/users/:userId/roles` | Set user's roles (full replace) |

### Permission Management (Tenant-Scoped)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/tenants/:tenantId/permissions` | List permissions (paginated) |
| POST | `/admin/tenants/:tenantId/permissions` | Create permission |
| PUT | `/admin/tenants/:tenantId/permissions/:id` | Update permission |
| DELETE | `/admin/tenants/:tenantId/permissions/:id` | Delete permission |

### Admin API Security

- All admin endpoints are protected by RBAC itself
- `system_admin` role: can manage all tenants, users, roles, permissions
- `tenant_admin` role: can only manage resources within their assigned tenant
- Initial migration creates the `system_admin` role and assigns it to the configured super admin username
- Admin users authenticate through the existing JWT/backend login flow — no separate admin auth

---

## Configuration

### New Config Section

```yaml
rbac:
  enabled: true                        # Master switch
  db:
    driver: "postgres"
    dsn: "postgres://user:pass@localhost:5432/gateway?sslmode=disable"
    maxOpenConns: 25
    maxIdleConns: 5
    connMaxLifetimeMinutes: 30
  adminPath: "/admin"                  # Admin API prefix
  superAdmin:                          # Initial super admin (role assigned on first migration)
    username: "admin"                  # Must match a username from the backend login service
  pagination:
    defaultPageSize: 20
    maxPageSize: 100
```

### Toggle Behavior

**`rbac.enabled: true`:**
1. Connect to PostgreSQL, run migrations
2. Initialize Casbin enforcer, load policies from DB
3. Register admin API routes under `adminPath`
4. Inject `RBACFilter` into middleware chain
5. `AuthFilter` operates in JWT-only mode

**`rbac.enabled: false`:**
1. No PostgreSQL connection
2. No Casbin initialization
3. No admin API routes registered
4. `AuthFilter` operates in full mode (JWT + privilege matching) — **existing behavior unchanged**

---

## Code Structure

### New Files

```
pkg/rbac/
├── model.go               # Casbin model definition (embedded string)
├── enforcer.go            # Casbin enforcer init & policy reload
├── middleware.go           # RBACFilter middleware
├── store/
│   ├── db.go              # PostgreSQL connection & migration runner
│   ├── models.go          # DB model structs (User, Tenant, Role, Permission, etc.)
│   ├── user_repo.go       # User CRUD operations
│   ├── tenant_repo.go     # Tenant CRUD operations
│   ├── role_repo.go       # Role CRUD operations
│   ├── permission_repo.go # Permission CRUD operations
│   └── migrations/
│       ├── 001_init_schema.up.sql
│       └── 001_init_schema.down.sql
├── handler/
│   ├── tenant_handler.go  # Tenant management handlers
│   ├── user_handler.go    # User management handlers
│   ├── role_handler.go    # Role management handlers
│   ├── permission_handler.go # Permission management handlers
│   └── response.go        # Pagination & error response structures
└── admin.go               # Admin API route registration
```

### Modified Files

1. **`pkg/config/config.go`** — Add `RBACConfig` struct and parsing
2. **`pkg/middleware/authFilter.go`** — Split JWT verification from privilege matching; add `rbacEnabled` flag to skip privilege matching when RBAC is active
3. **`internal/api-gateway/route.go`** — Conditionally inject `RBACFilter` based on `rbac.enabled`
4. **`internal/api-gateway/gateway.go`** — Initialize RBAC on startup (DB, migration, Casbin, admin routes)
5. **`configs/api-gateway.yaml.template`** — Add `rbac` config section example

### New Dependencies

- `github.com/casbin/casbin/v2` — Policy engine
- `github.com/casbin/casbin-pg-adapter` — Casbin PostgreSQL adapter
- `github.com/jackc/pgx/v5` — PostgreSQL driver
- `github.com/golang-migrate/migrate/v4` — Database migrations

---

## Error Handling

| Scenario | HTTP Status | Response |
|----------|-------------|----------|
| JWT invalid/missing | 401 Unauthorized | Existing behavior unchanged |
| RBAC deny (Casbin enforce = false) | 403 Forbidden | `{"error": {"code": "FORBIDDEN", "message": "insufficient permissions"}}` |
| Unknown hostname (no tenant) | 403 Forbidden | `{"error": {"code": "UNKNOWN_TENANT", "message": "..."}}` |
| Admin API input validation | 400 Bad Request | `{"error": {"code": "INVALID_INPUT", "message": "..."}}` |
| Admin API resource not found | 404 Not Found | `{"error": {"code": "NOT_FOUND", "message": "..."}}` |
| DB connection failure at startup | Fatal exit | Log error and exit |
| DB connection failure at runtime | 500 Internal Server Error | Log error, return 500 |

---

## Testing Strategy

### Unit Tests

- Each repository method (user_repo, tenant_repo, role_repo, permission_repo)
- Each handler (request parsing, validation, response format)
- RBACFilter middleware logic (allow/deny scenarios)
- Casbin model correctness (policy matching, role inheritance)
- Hostname-to-tenant resolution
- Toggle on/off behavior

### Integration Tests

- Use `testcontainers-go` to spin up PostgreSQL containers
- Full workflow: create tenant → create role → create permission → assign role → verify request enforcement
- Migration up/down correctness
- Admin API end-to-end tests

### Middleware Chain Tests

- Verify RBAC on: requests are checked against Casbin
- Verify RBAC off: requests fall back to existing privilege matching
- Verify no regression in existing authentication flow

---

## Migration & Bootstrap

### First-Time Setup

1. Run SQL migration `001_init_schema.up.sql` — creates all tables and indexes
2. Seed data:
   - Create `__system__` tenant (virtual tenant for system-level admin operations, not tied to any hostname)
   - Create `system_admin` role in the `__system__` tenant
   - Create user record for the configured `superAdmin.username`
   - Assign `system_admin` role to that user in the `__system__` tenant
3. The super admin authenticates through the existing JWT/backend login flow using the same username

### Subsequent Migrations

- Numbered migration files (002, 003, ...) for schema changes
- `golang-migrate` tracks applied migrations in a `schema_migrations` table
- Up/down migrations for rollback support
