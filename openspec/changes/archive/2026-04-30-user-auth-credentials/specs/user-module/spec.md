## ADDED Requirements

### Requirement: Standalone user/tenant module at pkg/user
The system SHALL provide a `pkg/user/` module that owns user, tenant, and tenant-domain entities with its own database connection, migrations, repos, and HTTP handlers. Both `pkg/auth/` and `pkg/rbac/` SHALL depend on `pkg/user/store` for user and tenant data access.

#### Scenario: Module initializes independently
- **WHEN** `user.New(ctx, cfg)` is called during gateway startup
- **THEN** the module SHALL establish its own `*gorm.DB` connection, run migrations, and return a `*User` instance exposing store repos

#### Scenario: RBAC references user module
- **WHEN** `rbac.New()` is called after `user.New()`
- **THEN** RBAC SHALL accept user/tenant repos from `pkg/user/store` instead of creating its own

### Requirement: Tenant-scoped users (users.tenant_id)
Each user record SHALL have a `tenant_id` foreign key referencing `tenants(id)`. A user belongs to exactly one tenant.

#### Scenario: User created with tenant
- **WHEN** a user is created via the admin API
- **THEN** the `users` row SHALL have a non-null `tenant_id`

#### Scenario: User cannot exist without tenant
- **WHEN** an attempt is made to create a user without `tenant_id`
- **THEN** the database SHALL reject the insert (NOT NULL constraint)

### Requirement: Tenant-scoped uniqueness for username, email, phone
Username SHALL be unique within a tenant via `UNIQUE(tenant_id, username)`. Email and phone SHALL be unique within a tenant via partial unique indexes `WHERE email IS NOT NULL` and `WHERE phone IS NOT NULL` respectively.

#### Scenario: Same username in different tenants
- **WHEN** tenant A has user `alice` and tenant B creates user `alice`
- **THEN** both records SHALL be accepted (different tenant_id)

#### Scenario: Duplicate username in same tenant
- **WHEN** tenant A has user `alice` and another user with username `alice` is created in tenant A
- **THEN** the database SHALL reject the insert (unique constraint violation)

#### Scenario: Null email does not conflict
- **WHEN** two users in the same tenant both have `email = NULL`
- **THEN** both records SHALL be accepted (partial index excludes NULLs)

### Requirement: tenant_users table removed
The `tenant_users` join table SHALL be removed. User-tenant association is determined solely by `users.tenant_id`.

#### Scenario: Migration drops tenant_users
- **WHEN** the user module migration runs
- **THEN** existing `tenant_users` data SHALL be migrated to `users.tenant_id` and the `tenant_users` table SHALL be dropped

#### Scenario: Migration handles existing data
- **WHEN** a user has a `tenant_users` row
- **THEN** the migration SHALL set `users.tenant_id` from that row before dropping the table

### Requirement: Domain trie for tenant resolution
The domain-to-tenant resolution trie (`DomainTrie`) SHALL live in `pkg/user/` as it is a tenant concern, not an authorization concern.

#### Scenario: Domain trie resolves tenant
- **WHEN** a request arrives for `app.example.com`
- **THEN** the domain trie SHALL return the matching tenant code based on exact or wildcard domain patterns

### Requirement: User/tenant admin API handlers
The `pkg/user/` module SHALL expose HTTP handlers for user and tenant CRUD operations, including tenant-domain management.

#### Scenario: User CRUD endpoints
- **WHEN** the user module is initialized
- **THEN** it SHALL provide handlers for: list users, create user, get user, update user, delete user (soft-delete)

#### Scenario: Tenant CRUD endpoints
- **WHEN** the user module is initialized
- **THEN** it SHALL provide handlers for: list tenants, create tenant, get tenant, update tenant, delete tenant

#### Scenario: Tenant domain endpoints
- **WHEN** the user module is initialized
- **THEN** it SHALL provide handlers for: list domains for tenant, create domain, delete domain

### Requirement: User module migration runs before RBAC
The user module's migrations SHALL execute before RBAC migrations to ensure `users` and `tenants` tables exist for RBAC's foreign key references.

#### Scenario: Initialization order
- **WHEN** the gateway starts
- **THEN** `user.New()` SHALL be called before `rbac.New()` to guarantee migration order
