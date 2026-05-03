## ADDED Requirements

### Requirement: Unified database configuration
The user module configuration SHALL be the single source of truth for PostgreSQL database connection parameters. The RBAC module SHALL NOT define its own database connection configuration.

#### Scenario: RBAC config has no DB section
- **WHEN** the configuration YAML is loaded
- **THEN** the `rbac` section SHALL NOT contain `db.dsn`, `db.maxOpenConns`, `db.maxIdleConns`, `db.connMaxLifetimeMinutes`

#### Scenario: RBAC gets DB from user module
- **WHEN** the RBAC module is initialized
- **THEN** it SHALL receive the `*gorm.DB` instance from the user module
- **AND** it SHALL NOT open a separate PostgreSQL connection pool

### Requirement: No hardcoded super admin in configuration
The configuration SHALL NOT contain `superAdmin.username` in either the `user` or `rbac` sections. Super administrator creation is handled by the `init-super-admin` CLI command.

#### Scenario: superAdmin config removed from user
- **WHEN** the configuration YAML is loaded
- **THEN** the `user` section SHALL NOT contain a `superAdmin` key

#### Scenario: superAdmin config removed from rbac
- **WHEN** the configuration YAML is loaded
- **THEN** the `rbac` section SHALL NOT contain a `superAdmin` key

### Requirement: RBAC configuration contains only RBAC-specific settings
The `rbac` configuration section SHALL contain only: `enabled`, `adminPath`, and `pagination`.

#### Scenario: Minimal RBAC config
- **WHEN** the configuration YAML defines `rbac.enabled: true` and `rbac.adminPath: /admin`
- **THEN** the RBAC module SHALL initialize successfully using the user module's database

### Requirement: User configuration contains DB and pagination
The `user` configuration section SHALL contain `db` (database connection parameters) and `pagination` (default page size, max page size).

#### Scenario: User config structure
- **WHEN** the configuration YAML defines `user.db.dsn` and `user.pagination.defaultPageSize`
- **THEN** the user module SHALL use these values for database connection and API pagination
