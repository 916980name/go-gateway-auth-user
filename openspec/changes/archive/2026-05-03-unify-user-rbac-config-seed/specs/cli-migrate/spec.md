## ADDED Requirements

### Requirement: Migrate command runs all database migrations
The system SHALL provide a CLI command `api-gateway migrate` that reads the YAML configuration to obtain the database DSN and executes all pending SQL migrations for user and RBAC modules in order.

#### Scenario: Fresh database migration
- **WHEN** `api-gateway migrate` is executed with a valid config pointing to an empty PostgreSQL database
- **THEN** the command SHALL create all user module tables (tenants, tenant_domains, users, user_credentials) and all RBAC module tables (roles, permissions, user_roles, role_permissions)
- **AND** the command SHALL exit with code 0

#### Scenario: Idempotent migration
- **WHEN** `api-gateway migrate` is executed on a database that already has all migrations applied
- **THEN** the command SHALL detect no pending migrations and exit with code 0 without errors

#### Scenario: Config file not found
- **WHEN** `api-gateway migrate` is executed without a valid config file
- **THEN** the command SHALL print an error message and exit with a non-zero code

### Requirement: Migrate command seeds default data
The system SHALL, as part of `api-gateway migrate`, create default bootstrap data: the `__system__` tenant with its domain pattern, and the `system_admin` and `tenant_admin` roles.

#### Scenario: Seed on first run
- **WHEN** `api-gateway migrate` is executed on a freshly migrated database
- **THEN** a tenant with code `__system__` SHALL be created
- **AND** a tenant domain with pattern `__system__` SHALL be created for the system tenant
- **AND** a role with code `system_admin` SHALL be created in the system tenant
- **AND** a role with code `tenant_admin` SHALL be created in the system tenant

#### Scenario: Seed is idempotent
- **WHEN** `api-gateway migrate` is executed multiple times
- **THEN** the seed data SHALL NOT be duplicated (upsert behavior)

### Requirement: Migrate command does NOT create super admin user
The migrate command SHALL NOT create any user records or credentials. Super admin user creation is handled exclusively by `init-super-admin`.

#### Scenario: No users after migrate
- **WHEN** `api-gateway migrate` completes successfully
- **THEN** no users SHALL exist in the database

### Requirement: Migrate command respects config file flag
The system SHALL support the `-c` / `--config` flag on the migrate command to specify a non-default configuration file path.

#### Scenario: Custom config path
- **WHEN** `api-gateway migrate -c /path/to/config.yaml` is executed
- **THEN** the command SHALL read configuration from `/path/to/config.yaml`
