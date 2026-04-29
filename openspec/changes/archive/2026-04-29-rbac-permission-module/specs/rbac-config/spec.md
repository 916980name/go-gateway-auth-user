## ADDED Requirements

### Requirement: RBAC configuration section in gateway config
The system SHALL support an `rbac` section in the gateway YAML config with fields for `enabled`, `db` (PostgreSQL connection), `adminPath`, `superAdmin.username`, and `pagination` defaults.

#### Scenario: Full RBAC config is parsed
- **WHEN** the config YAML contains a complete `rbac` section with `enabled: true`, `db.dsn`, `adminPath`, `superAdmin.username`, `pagination.defaultPageSize`, and `pagination.maxPageSize`
- **THEN** the system SHALL parse all fields into the `RBACConfig` struct

#### Scenario: Minimal config with defaults
- **WHEN** the config YAML contains `rbac.enabled: true` and `rbac.db.dsn` but omits optional fields
- **THEN** the system SHALL use defaults: `adminPath: "/admin"`, `pagination.defaultPageSize: 20`, `pagination.maxPageSize: 100`, `db.maxOpenConns: 25`, `db.maxIdleConns: 5`, `db.connMaxLifetimeMinutes: 30`

### Requirement: Feature toggle controls RBAC initialization
The `rbac.enabled` flag SHALL be the master switch controlling all RBAC behavior.

#### Scenario: RBAC enabled — full initialization
- **WHEN** `rbac.enabled` is `true`
- **THEN** the system SHALL: connect to PostgreSQL, run migrations, initialize Casbin enforcer, load policies from DB, register admin API routes under `adminPath`, inject `RBACFilter` into middleware chain, and set `AuthFilter` to JWT-only mode

#### Scenario: RBAC disabled — zero impact
- **WHEN** `rbac.enabled` is `false` (or the `rbac` section is absent)
- **THEN** the system SHALL NOT connect to PostgreSQL, NOT initialize Casbin, NOT register admin routes, NOT inject `RBACFilter`, and `AuthFilter` SHALL operate in its original full mode (JWT + privilege matching)

#### Scenario: Missing rbac section treated as disabled
- **WHEN** the config YAML has no `rbac` section at all
- **THEN** the system SHALL behave as if `rbac.enabled: false`

### Requirement: Database connection failure at startup is fatal
When RBAC is enabled and the PostgreSQL connection fails at startup, the gateway SHALL exit with a fatal error.

#### Scenario: DB unreachable on startup
- **WHEN** `rbac.enabled` is `true` and the configured DSN is unreachable
- **THEN** the gateway SHALL log the error and exit (not start in a degraded state)

### Requirement: Config struct extends existing Config
The `RBACConfig` struct SHALL be added as a field on the existing `Config` struct and parsed via Viper alongside existing configuration.

#### Scenario: RBACConfig coexists with existing config
- **WHEN** the gateway config YAML contains both existing fields (`sites`, `db`, `rateLimiters`) and the new `rbac` section
- **THEN** all fields SHALL be parsed correctly without conflict
