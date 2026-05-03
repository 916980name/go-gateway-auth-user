## 1. Config De-duplication

- [x] 1.1 Remove `SuperAdminConfig` and `SuperAdmin` field from `pkg/user/config.go`
- [x] 1.2 Remove `DBConfig`, `SuperAdminConfig` and corresponding fields from `pkg/rbac/config.go`, keep only `Enabled`, `AdminPath`, and `PaginationConfig`
- [x] 1.3 Remove `ApplyDefaults()` logic for DB connection parameters from `pkg/rbac/config.go`
- [x] 1.4 Remove `firstSchemaFromPostgresDSN` from `pkg/rbac/config.go` (no longer needed)
- [x] 1.5 Update `pkg/config/config.go` struct tags — no changes needed

## 2. Seed Script Refactoring

- [x] 2.1 Remove super admin user creation from `pkg/user/store/seed.go` — keep only `__system__` tenant + domain seed
- [x] 2.2 Update `store.Seed()` in `pkg/user/store/seed.go` to no longer accept `superAdminUsername` parameter
- [x] 2.3 Remove super admin user lookup and role assignment from `pkg/rbac/store/seed.go` — keep only `system_admin` + `tenant_admin` role creation
- [x] 2.4 Update `store.Seed()` in `pkg/rbac/store/seed.go` to no longer accept `superAdminUsername` parameter

## 3. Module Initialization Changes

- [x] 3.1 Remove `store.RunMigrations()` and `store.Seed()` calls from `pkg/user/user.go` `New()`
- [x] 3.2 Add `func (m *Module) DB() *gorm.DB` accessor to `pkg/user/user.go`
- [x] 3.3 Remove `store.RunMigrations()`, `store.Seed()`, and `store.NewDB()` calls from `pkg/rbac/rbac.go` `New()`
- [x] 3.4 Change `rbac.New()` signature to accept `dsn string` and `db *gorm.DB` parameters
- [x] 3.5 Pass received `*gorm.DB` to RBAC repository constructors (`NewRoleRepo`, `NewPermissionRepo`, `NewPolicySync`)
- [x] 3.6 Use received `dsn` parameter instead of `cfg.DB.DSN` for Casbin enforcer initialization

## 4. CLI Commands Implementation

- [x] 4.1 Create `internal/api-gateway/migrate.go` — `migrateCommand()` cobra subcommand
- [x] 4.2 Create `internal/api-gateway/initsuperadmin.go` — `initSuperAdminCommand()` cobra subcommand

## 5. Gateway Integration

- [x] 5.1 Update `internal/api-gateway/gateway.go` `run()` to pass `userMod.DB()` and `cfg.User.DB.DSN` to `rbac.New()`
- [x] 5.2 Register `migrateCommand()` and `initSuperAdminCommand()` as subcommands in `NewCommand()`
- [x] 5.3 Remove migration/seed-related log messages from `run()` that no longer apply
- [x] 5.4 Add `userMod.DB()` nil-check before passing to rbac.New() when RBAC is enabled

## 6. Configuration Template

- [x] 6.1 Add `user:` section with `db` and `pagination` subsections to `configs/api-gateway.yaml.template`
- [x] 6.2 Remove `db`, `schema`, `superAdmin` from the `rbac:` section in the template, uncomment the `rbac:` section
- [x] 6.3 Add a comment in the template explaining that migrate must be run before starting the server

## 7. Verification

- [x] 7.1 Run `go build ./...` to ensure compilation
- [x] 7.2 Run `go vet ./...` for static analysis
- [x] 7.3 Run existing tests (`go test ./...`)
- [ ] 7.4 Manually verify `api-gateway migrate` creates tables and seeds data
- [ ] 7.5 Manually verify `api-gateway init-super-admin testadmin` creates user and outputs password
- [ ] 7.6 Manually verify `api-gateway` (serve mode) starts without running migrations
