## Context

当前 user 和 rbac 模块各自维护一套几乎相同的配置结构体（DBConfig、SuperAdminConfig、PaginationConfig），各自的 store 包中存在完全相同的 `db.go` 和 `migrate.go` 代码，各自的 seed 也分散在两处且紧密耦合。启动时 `user.New()` 和 `rbac.New()` 都会自动执行迁移和种子，导致每次启动都有不必要的 DB 操作开销。

RBAC 模块本身已依赖 user 模块（RBAC migrations 引用了 user 管理的 tenants/users 表，RBAC 通过 `user.Module` 调用 `ResolveTenant` 和 `Upsert`），但配置和 DB 连接层面并未体现这一依赖关系，导致 `user.superAdmin.username` 和 `rbac.superAdmin.username` 必须手动保持一致。

## Goals / Non-Goals

**Goals:**
- 消除 user 和 rbac 之间的配置重复（DB、SuperAdmin、Pagination）
- RBAC 复用 user 模块的数据库连接，不再创建独立 DB 池
- 迁移和种子从模块初始化中解耦，改为独立 CLI 命令执行
- 超级管理员用户名从配置中移除，改为 CLI 命令动态创建并生成随机密码

**Non-Goals:**
- 不重构 Casbin adapter 的连接方式（仍独立使用 DSN 创建自己的连接池）
- 不改变 user 和 rbac 的 API 端点路由
- 不改变 login/logout 流程
- 不移除或合并 user/store/db.go 和 rbac/store/db.go（按用户要求保留在各自包中）

## Decisions

### D1: RBAC 复用 user 的 `*gorm.DB`，Casbin 通过传入的 DSN 独立连接

```
func New(ctx context.Context, cfg Config, dsn string, db *gorm.DB, userMod *user.Module) (*RBAC, error)
```

- `db` 参数：来自 `user.Module` 创建的 GORM 连接池，用于 RBAC 业务 CRUD
- `dsn` 参数：仅传递给 Casbin Enforcer 创建适配器，Casbin 需要自己的连接池
- `cfg Schema` 字段：保留用于 Casbin 表命名，从 DSN 的 search_path 自动提取

**替代方案**: RBAC 保留独立 DB 配置但加验证 → 更复杂且配置冗余，不选。

### D2: 新 CLI 命令用 Cobra 子命令实现

```
api-gateway migrate             [-c config.yaml]
api-gateway init-super-admin <username>  [-c config.yaml]
```

两个子命令均通过 viper 读取同一个 YAML 配置，从中获取 `user.db.dsn`。
- `migrate` 依次调用 `user/store/migrate.go` 和 `rbac/store/migrate.go` 的迁移函数，然后调用 seed 函数
- `init-super-admin` 直接操作 DB：upsert 用户、创建凭证、分配角色

### D3: 种子数据拆分

| 数据 | 命令 |
|---|---|
| `__system__` 租户 + 域名 | `api-gateway migrate` |
| `system_admin` + `tenant_admin` 角色 | `api-gateway migrate` |
| 超级管理员用户 + 密码凭证 + 角色分配 | `api-gateway init-super-admin <username>` |

`user/store/seed.go` 保留但仅创建 `__system__` 租户和域名，移除用户创建。
`rbac/store/seed.go` 保留但仅创建两个默认角色，移除超管用户查找和角色分配。

### D4: 新函数签名

```go
// user/user.go
func New(ctx context.Context, cfg Config) (*Module, error)
// 内部: DB 连接 + RefreshTenantMap，不再调用 migrate/seed
// 新增: func (m *Module) DB() *gorm.DB — 对外暴露 DB 供 RBAC 复用

// rbac/rbac.go
func New(ctx context.Context, cfg Config, dsn string, db *gorm.DB, userMod *user.Module) (*RBAC, error)
// 内部: 用传入的 db 创建 repos + policySync，用传入的 dsn 创建 Casbin enforcer

// 新增 store 函数 (供 migrate 命令调用)
func MigrateAll(dsn string) error  // 依次执行 user 迁移 → rbac 迁移 → 种子
func SeedAll(dsn string) error     // 仅创建租户 + 角色（不含超管）
```

### D5: 密码生成

使用 `crypto/rand` 生成 16 字符随机密码，包含大小写字母和数字。通过 bcrypt 哈希后写入 `user_credentials` 表。明文密码仅输出到 stdout，不写入任何日志文件。

## Risks / Trade-offs

- **风险**: `init-super-admin` 输出的明文密码出现在终端历史中 → 命令结束时提醒用户清除终端历史 / 立即修改密码
- **风险**: 移除启动时的自动迁移意味着部署流程变更，缺少 migrate 步骤会导致表不存在 → migrate 命令幂等（golang-migrate 的 `migrate.ErrNoChange` 已处理），部署脚本中增加 migrate 前置步骤
- **风险**: RBAC 不再有独立 DB 配置，不再能从独立数据库读取 → 如果未来需要读写分离/独立 DB，需重新加入 → 当前 RBAC 迁移引用 user 表，必须在同一数据库，短期无此需求
- **风险**: `rbac.Config` 移除 `Enabled` 与否待定 → 保留 `enabled` 字段在 rbac 配置中，因为 RBAC 功能本身就是可选启用的
