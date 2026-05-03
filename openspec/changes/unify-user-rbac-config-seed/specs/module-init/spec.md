## ADDED Requirements

### Requirement: Module initialization does not run migrations
The `user.New()` and `rbac.New()` functions SHALL NOT execute database migrations during initialization. Migrations are handled exclusively by `api-gateway migrate`.

#### Scenario: user.New() skips migration
- **WHEN** `user.New(ctx, cfg)` is called
- **THEN** it SHALL connect to the database but SHALL NOT call `store.RunMigrations()`

#### Scenario: rbac.New() skips migration
- **WHEN** `rbac.New(ctx, cfg, dsn, db, userMod)` is called
- **THEN** it SHALL NOT call `store.RunMigrations()`

### Requirement: Module initialization does not run seed data
The `user.New()` and `rbac.New()` functions SHALL NOT execute seed data insertion during initialization. Seed data is handled by `api-gateway migrate`.

#### Scenario: user.New() skips seed
- **WHEN** `user.New(ctx, cfg)` is called
- **THEN** it SHALL NOT call `store.Seed()`

#### Scenario: rbac.New() skips seed
- **WHEN** `rbac.New(ctx, cfg, dsn, db, userMod)` is called
- **THEN** it SHALL NOT call `store.Seed()`

### Requirement: User module exposes database connection
The user module SHALL expose its `*gorm.DB` instance so that the RBAC module can reuse it.

#### Scenario: DB accessor
- **WHEN** `userMod.DB()` is called
- **THEN** it SHALL return the `*gorm.DB` instance created during `user.New()`

### Requirement: RBAC module accepts shared database connection
The RBAC module's constructor SHALL accept a `*gorm.DB` parameter and use it for all business data operations instead of creating its own connection pool.

#### Scenario: Shared connection
- **WHEN** `rbac.New(ctx, cfg, dsn, sharedDB, userMod)` is called
- **THEN** all RBAC repositories (RoleRepo, PermissionRepo, PolicySync) SHALL use the `sharedDB` for queries
- **AND** the Casbin enforcer SHALL create its own connection pool using the provided `dsn` parameter
