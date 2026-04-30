## MODIFIED Requirements

### Requirement: PostgreSQL schema for RBAC entities
The system SHALL use PostgreSQL to store RBAC entities with `BIGSERIAL` auto-increment primary keys, `UUID` as external business identifiers, and all foreign keys referencing integer `id` columns.

#### Scenario: Schema contains all required tables
- **WHEN** the RBAC migration is applied (after user module migration)
- **THEN** the following tables SHALL exist in `pkg/rbac/store/migrations/`: `roles`, `permissions`, `user_roles`, `role_permissions`

#### Scenario: User and tenant tables owned by user module
- **WHEN** the RBAC module initializes
- **THEN** it SHALL NOT create or migrate the `users`, `tenants`, `tenant_domains` tables (these are owned by `pkg/user/`)

#### Scenario: UUID uniqueness is enforced
- **WHEN** any entity is created in `roles` or `permissions`
- **THEN** the `uuid` column SHALL be auto-generated via `gen_random_uuid()` and enforced as `NOT NULL UNIQUE`

### Requirement: Tenant-scoped users replace global users with tenant_users
Users SHALL be scoped to a single tenant via `users.tenant_id`. The `tenant_users` join table SHALL NOT exist. Roles and permissions SHALL remain scoped to tenants via their own `tenant_id` columns.

#### Scenario: User belongs to one tenant
- **WHEN** a user record exists with `tenant_id = 1`
- **THEN** that user SHALL only have roles and permissions within tenant 1

#### Scenario: Tenant-scoped role uniqueness
- **WHEN** a role with code `admin` exists in tenant A
- **THEN** a role with code `admin` MAY also exist in tenant B as a separate entity (enforced by `UNIQUE(tenant_id, code)`)

### Requirement: RBAC uses user module repos
The RBAC module SHALL NOT own user or tenant repositories. It SHALL accept `*store.UserRepo` and `*store.TenantRepo` from `pkg/user/store` during initialization.

#### Scenario: RBAC initialization with external repos
- **WHEN** `rbac.New(ctx, cfg, userRepo, tenantRepo, domainRepo)` is called
- **THEN** RBAC SHALL use these repos for user/tenant lookups instead of creating its own

#### Scenario: Auto-provision user uses user module repo
- **WHEN** RBAC needs to auto-provision a user
- **THEN** it SHALL call the user repo from `pkg/user/store`, not its own internal repo

### Requirement: Proper indexing for query performance
The system SHALL create indexes on foreign key columns used in joins and lookups.

#### Scenario: Foreign key indexes exist
- **WHEN** the RBAC schema is created
- **THEN** indexes SHALL exist on: `roles(tenant_id)`, `permissions(tenant_id)`, `user_roles(user_id)`, `user_roles(tenant_id)`, `role_permissions(role_id)`

### Requirement: Casbin model uses RBAC with domains
The system SHALL use a Casbin model with `request_definition: r = sub, dom, obj, act`, `policy_definition: p = sub, dom, obj, act`, `role_definition: g = _, _, _` (role assignment with domain), and matcher using `keyMatch2` for path matching.

#### Scenario: Casbin policy is loaded from PostgreSQL
- **WHEN** the gateway starts with RBAC enabled
- **THEN** all policies SHALL be loaded from PostgreSQL via the Casbin pg-adapter into the in-memory engine

#### Scenario: Policy reload after management API changes
- **WHEN** a role, permission, or role-permission assignment is changed via the admin API
- **THEN** the system SHALL call `enforcer.LoadPolicy()` to refresh the in-memory Casbin engine

## REMOVED Requirements

### Requirement: Global users with tenant-scoped permissions
**Reason**: Replaced by tenant-scoped users. Users are no longer global entities that join multiple tenants. Each user belongs to exactly one tenant via `users.tenant_id`.
**Migration**: Existing `tenant_users` data is migrated to `users.tenant_id` by the user module migration. Code referencing `tenant_users` must be updated to use `users.tenant_id` instead.

### Requirement: Bootstrap seed data on first migration
**Reason**: Seed data logic moves to `pkg/user/` for tenant/user seeding. RBAC retains only role/permission seeding that depends on user module having already seeded the system tenant and super admin user.
**Migration**: `store.Seed()` in RBAC is simplified to only create `system_admin` role and assign it, assuming the `__system__` tenant and super admin user already exist (created by user module).
