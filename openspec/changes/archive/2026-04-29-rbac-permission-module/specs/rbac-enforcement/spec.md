## ADDED Requirements

### Requirement: RBACFilter middleware enforces permissions via Casbin
The system SHALL provide an `RBACFilter` middleware that intercepts requests after `AuthFilter` and enforces permissions using the Casbin engine with the RBAC-with-domains model (`sub, dom, obj, act`).

#### Scenario: Authorized request passes through
- **WHEN** a user with role `admin` in tenant `site-a` requests `GET /api/users/123` and the `admin` role has a policy granting `GET` on `/api/users/*` in `site-a`
- **THEN** the `RBACFilter` SHALL allow the request to proceed to the next middleware

#### Scenario: Unauthorized request is denied
- **WHEN** a user with role `viewer` in tenant `site-a` requests `POST /api/users` and the `viewer` role has no policy granting `POST` on `/api/users` in `site-a`
- **THEN** the `RBACFilter` SHALL return HTTP 403 Forbidden with error code `FORBIDDEN`

#### Scenario: Path parameter matching with keyMatch2
- **WHEN** a policy grants access to `/api/users/:id` and a request targets `/api/users/abc-123`
- **THEN** the `RBACFilter` SHALL match the request path against the policy using Casbin's `keyMatch2` function

### Requirement: Hostname-to-tenant resolution
The system SHALL resolve request hostnames to tenant codes using an in-memory map loaded from the database at startup and refreshed on tenant CRUD operations.

#### Scenario: Known hostname resolves to tenant
- **WHEN** a request arrives with hostname `app.example.com` and a tenant with `hostname = app.example.com` exists in the database
- **THEN** the `RBACFilter` SHALL resolve the hostname to the tenant's `code` and use it as the Casbin domain

#### Scenario: Unknown hostname is rejected
- **WHEN** a request arrives with a hostname that does not match any tenant in the database
- **THEN** the `RBACFilter` SHALL return HTTP 403 Forbidden with error code `UNKNOWN_TENANT`

#### Scenario: Tenant map refreshes on tenant changes
- **WHEN** a tenant is created, updated, or deleted via the admin API
- **THEN** the hostname-to-tenant map SHALL be refreshed to reflect the change

### Requirement: User auto-provisioning from JWT
The system SHALL automatically create a user record in the `users` table when a JWT-authenticated user is encountered for the first time.

#### Scenario: New user is auto-provisioned
- **WHEN** a JWT-authenticated request arrives and the username from the JWT does not exist in the `users` table
- **THEN** the system SHALL create a new user record with `username`, `email`, and `phone` extracted from the JWT claims

#### Scenario: Existing user is not duplicated
- **WHEN** a JWT-authenticated request arrives and the username already exists in the `users` table
- **THEN** the system SHALL use the existing user record without creating a duplicate

#### Scenario: Concurrent first requests for same user
- **WHEN** two concurrent requests arrive for a user not yet in the `users` table
- **THEN** the system SHALL use an upsert (`ON CONFLICT DO NOTHING`) so that exactly one record is created and no error occurs

### Requirement: AuthFilter operates in JWT-only mode when RBAC is enabled
When RBAC is enabled, the existing `AuthFilter` SHALL perform only JWT verification (token extraction, RSA verification, user info extraction, online cache check) and SHALL skip the `checkPrivileges()` step.

#### Scenario: RBAC enabled skips privilege matching
- **WHEN** `rbac.enabled` is `true` and a request passes JWT verification
- **THEN** `AuthFilter` SHALL set user info in context and proceed without calling `checkPrivileges()`

#### Scenario: RBAC disabled preserves existing behavior
- **WHEN** `rbac.enabled` is `false` and a request arrives on a route with `privilege` configured
- **THEN** `AuthFilter` SHALL perform both JWT verification and `checkPrivileges()` exactly as before

### Requirement: RBAC module is self-contained in pkg/rbac/
The `pkg/rbac/` package SHALL NOT import any gateway-specific packages (`pkg/proxy`, `pkg/middleware`, `pkg/config`, `pkg/log`, `pkg/common`). It SHALL use standard library interfaces (`net/http`, `log/slog`, `context`) so that third-party projects can also import it. The gateway integrates it via an adapter in `internal/api-gateway/`.

#### Scenario: RBAC middleware uses standard http.Handler
- **WHEN** the RBAC module exposes its enforcement middleware
- **THEN** it SHALL be a standard `func(http.Handler) http.Handler`, not the gateway's `proxy.Middleware`

#### Scenario: Gateway adapter bridges middleware types
- **WHEN** `internal/api-gateway/` integrates the RBAC middleware into the gateway chain
- **THEN** it SHALL convert between `http.Handler` middleware and the gateway's `proxy.Middleware` pattern

### Requirement: RBACFilter integrates into existing middleware chain
The adapted `RBACFilter` SHALL be injected into the middleware chain after `AuthFilter` and before `RateLimiter(User)`.

#### Scenario: Middleware chain order with RBAC enabled
- **WHEN** RBAC is enabled and a request is processed
- **THEN** the middleware chain SHALL be: `RequestFilter → RateLimiter(IP) → AuthFilter(JWT-only) → RBACFilter(adapted) → RateLimiter(User) → Backend Proxy`

#### Scenario: Middleware chain without RBAC
- **WHEN** RBAC is disabled
- **THEN** the `RBACFilter` SHALL NOT be present in the middleware chain, and the chain SHALL remain unchanged from existing behavior
