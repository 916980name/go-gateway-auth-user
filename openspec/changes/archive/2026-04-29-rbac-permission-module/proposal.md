## Why

The gateway currently uses simple route-level privilege matching that is hardcoded in config. This doesn't support multi-tenant permission isolation, dynamic role management, or centralized user-permission administration. As the platform scales to serve multiple business domains (sites), we need a proper RBAC system where users are global but permissions are tenant-scoped — enabling one user identity to hold different roles across different business domains.

## What Changes

- Add a complete RBAC module built on Casbin with PostgreSQL storage
- Introduce multi-tenant (domain-based) isolation: users are global, permissions are per-tenant
- Add a new `RBACFilter` middleware that enforces permissions via Casbin after JWT authentication
- Modify `AuthFilter` to skip privilege matching when RBAC is enabled (JWT-only mode)
- Add REST management API for dynamic CRUD of tenants, users, roles, and permissions
- Add feature toggle (`rbac.enabled`) — when disabled, existing behavior is completely unchanged
- Add user auto-provisioning from JWT claims on first encounter
- Add hostname-to-tenant resolution for request routing

## Capabilities

### New Capabilities

- `rbac-enforcement`: Casbin-based permission enforcement middleware with multi-tenant domain isolation, hostname-to-tenant resolution, and user auto-provisioning
- `rbac-data-model`: PostgreSQL schema for users, tenants, roles, permissions, and their relationships with migration support
- `rbac-admin-api`: REST management API for CRUD operations on tenants, users, roles, and permissions with pagination and tenant-scoped access control
- `rbac-config`: Configuration structure and feature toggle for enabling/disabling the RBAC module

### Modified Capabilities

_(none — no existing specs to modify)_

## Impact

- **New dependencies**: casbin/v2, casbin-pg-adapter, pgx/v5, golang-migrate/v4
- **Modified files**: config.go (new RBACConfig), authFilter.go (conditional privilege skip), route.go (inject RBACFilter), gateway.go (RBAC initialization)
- **New package**: `pkg/rbac/` with sub-packages for store, handler, middleware
- **Infrastructure**: Requires PostgreSQL database when RBAC is enabled
- **API surface**: New `/admin/*` endpoints for RBAC management
- **Zero impact when disabled**: No DB connection, no Casbin, no admin routes, existing auth flow unchanged
