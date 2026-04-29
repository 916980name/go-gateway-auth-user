## Context

The gateway currently uses a simple middleware chain per site: `RequestFilter → RateLimiter(IP) → AuthFilter → RateLimiter(User) → Backend Proxy`. Auth and privilege checking are combined in `AuthFilter`, which compares a route-level `privilege` string from config against the user's JWT-embedded privileges. This is static — no runtime management, no multi-tenant isolation.

The gateway uses `gorilla/mux` with host-based subrouting (`r.Host(site.HostName).Subrouter()`). Config is loaded via Viper from YAML (local or remote etcd). The proxy layer uses a middleware pattern: `type Middleware func(Proxy) Proxy` where `type Proxy func(ctx, *http.Request) (ctx, *http.Response, error)`.

## Goals / Non-Goals

**Goals:**
- Add Casbin-based RBAC with multi-tenant domain isolation
- Keep zero impact when `rbac.enabled: false` — no imports triggered, no connections, no routes
- **Module independence**: `pkg/rbac/` is a self-contained module with zero imports from gateway packages — designed for future extraction into a standalone unified identity/permission service
- Admin API runs on the same HTTP server, protected by RBAC itself
- Auto-provision users from JWT claims; roles require explicit admin assignment

**Non-Goals:**
- ABAC or fine-grained data-scope control
- User registration or password management
- Multi-instance policy sync (Redis Pub/Sub) — future extension
- Frontend admin UI
- Replacing the existing per-route privilege mechanism (it remains for non-RBAC mode)

## Decisions

### 1. Casbin with PostgreSQL adapter for policy storage

**Choice**: Casbin v2 with `casbin-pg-adapter` and in-memory enforcement.

**Rationale**: Casbin's RBAC-with-domains model maps directly to our multi-tenant requirement. The pg-adapter persists policies to PostgreSQL so they survive restarts. In-memory enforcement keeps latency negligible (~μs per check). Alternatives considered:
- OPA/Rego: more powerful but over-engineered for HTTP route + method matching
- Custom RBAC tables + query per request: higher latency, more code to maintain
- Casbin with file adapter: not suitable for dynamic management via API

### 2. PostgreSQL via pgx/v5

**Choice**: `pgx/v5` as the PostgreSQL driver with `golang-migrate/v4` for schema migrations.

**Rationale**: pgx is the most performant pure-Go Postgres driver with native type support. The gateway already uses Redis for caching but has no relational DB — PostgreSQL is the standard choice for RBAC data. Alternatives considered:
- SQLite: no network access, not suitable for multi-instance deployments
- MySQL: works but PostgreSQL's UUID support and `BIGSERIAL` are more natural

### 3. Conditional initialization — compile-time safe, runtime toggle

**Choice**: RBAC package is always compiled but only initialized when `rbac.enabled: true`. No build tags.

**Rationale**: Build tags add CI complexity. The RBAC package defines types and functions that are harmless when unused. At startup, `gateway.go` checks the config flag and either initializes the full RBAC stack (DB, migrations, Casbin, admin routes, middleware injection) or skips it entirely. This keeps the binary single-artifact while ensuring zero runtime cost when disabled.

### 4. Module independence — `pkg/rbac/` has zero gateway imports

**Choice**: The RBAC module (`pkg/rbac/`) is fully self-contained. It uses standard library interfaces (`net/http.Handler`, `log/slog`, `context`), defines its own config struct (`rbac.Config`), and exposes a clean public API. The gateway integration is a thin adapter layer in `internal/api-gateway/`.

**Rationale**: The RBAC module will likely be extracted into a standalone unified identity/permission service in the future. Any imports from gateway packages (`pkg/proxy`, `pkg/middleware`, `pkg/config`, `pkg/log`, `pkg/common`) would create coupling that makes extraction painful. The boundary is:
- `pkg/rbac/` — standalone module. Depends only on stdlib + its own dependencies (casbin, pgx, migrate). Exposes `http.Handler` for admin API, an `Enforce(user, domain, path, method) bool` function, and a standard `http.Handler` middleware wrapper.
- `internal/api-gateway/` — thin adapter. Converts between gateway's `proxy.Middleware` pattern and the RBAC module's `http.Handler`-based middleware. Reads gateway config and constructs `rbac.Config`. Mounts admin routes on the gateway's mux router.

Alternatives considered:
- Direct use of `proxy.Middleware` in RBAC module: simpler initially but creates a hard dependency on gateway internals
- Interface-based abstraction in gateway for RBAC to implement: over-engineered; a thin adapter is sufficient

### 5. AuthFilter splitting via flag, not separate middleware

**Choice**: Add an `rbacEnabled` parameter to `AuthFilter`. When true, skip `checkPrivileges()` after JWT verification.

**Rationale**: The current `AuthFilter` interleaves JWT verification and privilege checking in a single closure. Splitting into two separate middleware functions would require passing verified user info between them (extra context keys, ordering constraints). A flag is simpler — the existing code path just skips the privilege check when RBAC handles it. The adapter layer wraps the RBAC module's middleware into the gateway's chain after `AuthFilter`.

### 6. Admin API on the same mux router, gated by RBAC

**Choice**: The RBAC module exposes admin routes as an `http.Handler` (self-contained router). The gateway adapter mounts this handler under `/admin/*` on the main `mux.Router`.

**Rationale**: The RBAC module owns its own route definitions using standard `net/http` (e.g., `http.ServeMux` or a lightweight router internal to the module). The gateway just mounts the handler at a prefix. This keeps the module portable — when extracted to a standalone service, the same handler runs on its own HTTP server with zero changes. Separate listener means separate port, extra infra config, separate TLS — avoided by mounting on the existing router.

### 7. UUID externally, BIGSERIAL internally

**Choice**: API path params use UUID; all DB foreign keys use integer `id`; internal lookups resolve UUID → ID.

**Rationale**: UUIDs prevent enumeration and are safe for API exposure. Integer PKs give better B-tree performance and smaller indexes. The resolution layer is a thin `WHERE uuid = $1` query (indexed, O(1)).

## Risks / Trade-offs

- **Single-instance policy staleness** → When multiple gateway instances run, a management API call on instance A doesn't notify instance B. Mitigation: document as known limitation; future Redis Pub/Sub extension will solve this. For now, `LoadPolicy()` only runs on the instance that handled the admin request.

- **Cold-start migration on first boot** → `golang-migrate` runs on startup. If the DB is unreachable, the gateway exits fatally. Mitigation: fail-fast is intentional — a misconfigured RBAC-enabled gateway should not start silently without enforcement.

- **Auto-provisioning race condition** → Two concurrent requests from a new user could both try to INSERT. Mitigation: use `ON CONFLICT (username) DO NOTHING` upsert; second request just reads the existing row.

- **Admin API availability without tenant context** → Admin routes need RBAC enforcement but aren't tied to a real hostname/tenant. Mitigation: use a virtual `__system__` tenant for admin operations. System admins are assigned roles in this virtual tenant.

- **Casbin reload cost** → `LoadPolicy()` re-reads all policies from DB into memory. For very large policy sets this could spike latency briefly. Mitigation: acceptable for initial scope (hundreds to low thousands of policies). If growth exceeds this, switch to incremental `AddPolicy`/`RemovePolicy` calls instead of full reload.
