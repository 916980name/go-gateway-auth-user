# RBAC ORM Migration Design Spec

## Overview

Migrate the RBAC data access layer from raw SQL (pgx/v5) to GORM, so that struct field changes no longer require updating every related SQL statement.

## Decision Record

- **ORM framework**: GORM (v2) -- largest Go ORM community (39.7k stars), richest feature set, covers all existing access patterns
- **Schema migration**: Keep existing `golang-migrate` -- no GORM auto-migration
- **Casbin**: Untouched -- `casbin-pg-adapter` continues managing `casbin_rules` independently
- **Driver**: `gorm.io/driver/postgres` (uses pgx under the hood)

## Scope

### Files to modify (10 files)

| File | Change |
|------|--------|
| `pkg/rbac/store/models.go` | Add gorm struct tags to all 8 model structs |
| `pkg/rbac/store/db.go` | Replace `NewPool() *pgxpool.Pool` with `NewDB() *gorm.DB` |
| `pkg/rbac/store/user_repo.go` | Replace all raw SQL with GORM query API (12 methods) |
| `pkg/rbac/store/role_repo.go` | Replace all raw SQL with GORM query API (7 methods) |
| `pkg/rbac/store/permission_repo.go` | Replace all raw SQL with GORM query API (7 methods) |
| `pkg/rbac/store/tenant_repo.go` | Replace all raw SQL with GORM query API (7 methods) |
| `pkg/rbac/store/tenant_domain_repo.go` | Replace all raw SQL with GORM query API (6 methods) |
| `pkg/rbac/store/seed.go` | Replace pgxpool transaction with GORM transaction |
| `pkg/rbac/rbac.go` | Update initialization: `NewPool` -> `NewDB`, repo constructors take `*gorm.DB` |
| `go.mod` / `go.sum` | Add `gorm.io/gorm`, `gorm.io/driver/postgres`; remove direct `pgx/v5` dependency |

### Files NOT modified

- `pkg/rbac/store/migrate.go` and `pkg/rbac/store/migrations/*` -- schema migration stays as-is
- `pkg/rbac/enforcer.go`, `model.go`, `middleware.go`, `context.go`, `admin.go` -- no DB access changes
- All `pkg/rbac/handler/*.go` -- they call repo methods whose signatures don't change
- `internal/api-gateway/rbac_adapter.go` -- no DB access

## Detailed Design

### 1. Model Layer (`models.go`)

Add GORM struct tags to map table names and columns. GORM's default convention (snake_case) matches the existing schema, so most tags are for primary keys, indexes, defaults, and UUID generation.

Example for User:

```go
type User struct {
    ID          int64     `json:"-" gorm:"primaryKey;autoIncrement"`
    UUID        uuid.UUID `json:"uuid" gorm:"type:uuid;not null;uniqueIndex;default:gen_random_uuid()"`
    Username    string    `json:"username" gorm:"uniqueIndex;not null"`
    DisplayName string    `json:"displayName,omitempty" gorm:"column:display_name"`
    Email       string    `json:"email,omitempty"`
    Phone       string    `json:"phone,omitempty"`
    Status      int16     `json:"status" gorm:"default:1"`
    CreatedAt   time.Time `json:"createdAt"`
    UpdatedAt   time.Time `json:"updatedAt"`
}
```

All 8 model structs (User, Tenant, TenantDomain, TenantUser, Role, Permission, UserRole, RolePermission) receive the same treatment.

Non-table types (`PaginationParams`, `PaginatedResult`, `Pagination`, `DomainWithTenant`) are unchanged.

### 2. Database Connection Layer (`db.go`)

Replace `NewPool` with `NewDB`:

```go
func NewDB(ctx context.Context, cfg DBConfig) (*gorm.DB, error) {
    db, err := gorm.Open(postgres.Open(cfg.DSN), &gorm.Config{})
    if err != nil {
        return nil, fmt.Errorf("connect to postgres: %w", err)
    }
    sqlDB, _ := db.DB()
    sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
    sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
    sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetimeMinutes) * time.Minute)
    if err := sqlDB.PingContext(ctx); err != nil {
        sqlDB.Close()
        return nil, fmt.Errorf("ping postgres: %w", err)
    }
    return db, nil
}
```

Remove `pgxpool` import. The `DBConfig` struct stays unchanged.

### 3. Repository Layer

Each repo struct changes from `pool *pgxpool.Pool` to `db *gorm.DB`. Constructor functions change accordingly.

#### SQL-to-GORM Pattern Mapping

| Current pattern | GORM equivalent |
|----------------|-----------------|
| `INSERT ... RETURNING` via QueryRow+Scan | `db.Create(&model)` (GORM auto-fills ID, UUID, timestamps) |
| `SELECT ... WHERE uuid = $1` via QueryRow+Scan | `db.Where("uuid = ?", uid).First(&model)` |
| `SELECT ... LIMIT $1 OFFSET $2` via Query+rows loop | `db.Limit(n).Offset(off).Find(&items)` |
| `UPDATE ... SET col = COALESCE($2, col) ... RETURNING` | `db.Where("uuid = ?", uid).Updates(map)` then `db.First(&model)` to reload (two queries replace one) |
| `DELETE ... WHERE uuid = $1` | `db.Where("uuid = ?", uid).Delete(&Model{})` |
| `ON CONFLICT ... DO UPDATE` (upsert) | `db.Clauses(clause.OnConflict{...}).Create(&model)` |
| `ON CONFLICT ... DO NOTHING` | `db.Clauses(clause.OnConflict{DoNothing: true}).Create(&model)` |
| `ILIKE` search | `db.Where("username ILIKE ? OR display_name ILIKE ?", pat, pat)` |
| Count + paginated query | `db.Where(...).Count(&total)` then `db.Where(...).Limit().Offset().Find()` |
| JOIN queries | `db.Joins("JOIN table ON ...").Where(...).Find(...)` |
| Transaction + pgx.Batch | `db.Transaction(func(tx *gorm.DB) error { ... })` with loop of Creates |

#### Soft delete handling

The project uses a `status` field (1=active, 0=deleted) rather than GORM's built-in soft delete (`DeletedAt`). We will NOT use GORM's soft delete feature. Instead:
- `SoftDelete` methods do `db.Updates(map[string]any{"status": 0, "updated_at": time.Now()})`
- List methods filter with `.Where("status = ?", 1)`

#### Method signatures preserved

All repo method signatures (parameters and return types) remain unchanged so that handler code doesn't need modification.

### 4. Seed Function (`seed.go`)

- Change parameter from `pool *pgxpool.Pool` to `db *gorm.DB`
- Wrap in `db.Transaction(func(tx *gorm.DB) error { ... })`
- Replace each raw SQL upsert with `tx.Clauses(clause.OnConflict{...}).Create(&model)`

### 5. RBAC Initialization (`rbac.go`)

In `New()`:
- `store.NewPool(ctx, dbCfg)` -> `store.NewDB(ctx, dbCfg)`
- `store.Seed(ctx, pool, ...)` -> `store.Seed(ctx, db, ...)`
- All `store.NewXxxRepo(pool)` -> `store.NewXxxRepo(db)`
- RBAC struct field type changes: no pgxpool references

### 6. Dependencies

Add to `go.mod`:
- `gorm.io/gorm`
- `gorm.io/driver/postgres`

Remove direct dependency (if no other code uses it):
- `github.com/jackc/pgx/v5` -- note: only remove if nothing else imports it directly. `gorm.io/driver/postgres` pulls in pgx transitively.

Keep:
- `github.com/lib/pq` -- used by casbin-pg-adapter
- `github.com/golang-migrate/migrate/v4` -- still used for schema migrations
- `github.com/casbin/casbin/v2` -- policy engine
- `github.com/cychiuae/casbin-pg-adapter` -- casbin storage

## Testing Strategy

- Verify compile: `go build ./...`
- If integration tests exist, run them against a test database
- Manual verification: start the service and exercise RBAC admin endpoints (create tenant, create role, assign role to user, etc.)
