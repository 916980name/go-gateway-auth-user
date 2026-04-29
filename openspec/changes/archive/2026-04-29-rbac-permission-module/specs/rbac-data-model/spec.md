## ADDED Requirements

### Requirement: PostgreSQL schema for RBAC entities
The system SHALL use PostgreSQL to store RBAC entities with `BIGSERIAL` auto-increment primary keys, `UUID` as external business identifiers, and all foreign keys referencing integer `id` columns.

#### Scenario: Schema contains all required tables
- **WHEN** the migration `001_init_schema.up.sql` is applied
- **THEN** the following tables SHALL exist: `users`, `tenants`, `tenant_users`, `roles`, `permissions`, `user_roles`, `role_permissions`

#### Scenario: UUID uniqueness is enforced
- **WHEN** any entity is created in `users`, `tenants`, `roles`, or `permissions`
- **THEN** the `uuid` column SHALL be auto-generated via `gen_random_uuid()` and enforced as `NOT NULL UNIQUE`

### Requirement: Global users with tenant-scoped permissions
Users SHALL be global entities. Roles and permissions SHALL be scoped to tenants. A user MAY belong to multiple tenants with different roles in each.

#### Scenario: User belongs to multiple tenants
- **WHEN** a user is added to tenant A with role `admin` and tenant B with role `viewer`
- **THEN** the user SHALL have `admin` permissions in tenant A and `viewer` permissions in tenant B, with no cross-tenant leakage

#### Scenario: Tenant-scoped role uniqueness
- **WHEN** a role with code `admin` exists in tenant A
- **THEN** a role with code `admin` MAY also exist in tenant B as a separate entity (enforced by `UNIQUE(tenant_id, code)`)

### Requirement: Database migration management
The system SHALL use `golang-migrate/v4` to manage schema migrations with numbered up/down migration files.

#### Scenario: First migration creates schema
- **WHEN** the gateway starts with RBAC enabled and an empty database
- **THEN** migration `001_init_schema.up.sql` SHALL create all tables, indexes, and constraints

#### Scenario: Migration rollback
- **WHEN** migration `001_init_schema.down.sql` is applied
- **THEN** all RBAC tables SHALL be dropped cleanly

#### Scenario: Migration tracking
- **WHEN** migrations are applied
- **THEN** `golang-migrate` SHALL track applied versions in a `schema_migrations` table to prevent re-application

### Requirement: Bootstrap seed data on first migration
The system SHALL seed initial data after schema creation: a `__system__` virtual tenant, a `system_admin` role, the configured super admin user, and the role assignment.

#### Scenario: System tenant is created
- **WHEN** the RBAC module initializes for the first time
- **THEN** a tenant with code `__system__` SHALL be created (not tied to any external hostname)

#### Scenario: Super admin is bootstrapped
- **WHEN** the RBAC module initializes and `rbac.superAdmin.username` is configured
- **THEN** a user record for that username SHALL be created, assigned the `system_admin` role in the `__system__` tenant

### Requirement: Proper indexing for query performance
The system SHALL create indexes on foreign key columns used in joins and lookups.

#### Scenario: Foreign key indexes exist
- **WHEN** the schema is created
- **THEN** indexes SHALL exist on: `tenant_users(user_id)`, `tenant_users(tenant_id)`, `roles(tenant_id)`, `permissions(tenant_id)`, `user_roles(user_id)`, `user_roles(tenant_id)`, `role_permissions(role_id)`

### Requirement: Casbin model uses RBAC with domains
The system SHALL use a Casbin model with `request_definition: r = sub, dom, obj, act`, `policy_definition: p = sub, dom, obj, act`, `role_definition: g = _, _, _` (role assignment with domain), and matcher using `keyMatch2` for path matching.

#### Scenario: Casbin policy is loaded from PostgreSQL
- **WHEN** the gateway starts with RBAC enabled
- **THEN** all policies SHALL be loaded from PostgreSQL via the Casbin pg-adapter into the in-memory engine

#### Scenario: Policy reload after management API changes
- **WHEN** a role, permission, or role-permission assignment is changed via the admin API
- **THEN** the system SHALL call `enforcer.LoadPolicy()` to refresh the in-memory Casbin engine
