## Why

User 和 RBAC 模块存在配置重复、初始化脚本分散、超级管理员信息硬编码三个问题。两者事实上必须共享同一数据库且协同工作，但配置层面各自为政（DBConfig/SuperAdminConfig/PaginationConfig 均重复定义），迁移/种子代码散落在两个 package 的 store/migrate.go 和 store/seed.go 中，超级管理员用户名写死在 YAML 中却没有密码创建路径。本次变更统一配置、集中初始化、用 CLI 命令替代硬编码。

## What Changes

- **BREAKING**: 移除 `user.superAdmin` 配置项，超级管理员不再通过配置文件创建
- **BREAKING**: 移除 `rbac.db` 和 `rbac.superAdmin` 配置项，RBAC 复用 user 模块的数据库配置
- **BREAKING**: `user.New()` 和 `rbac.New()` 启动时不再自动执行数据库迁移和种子数据初始化
- 新增 `api-gateway migrate` 命令，统一执行建表迁移和系统租户/默认角色的种子数据
- 新增 `api-gateway init-super-admin <username>` 命令，生成随机密码并创建超级管理员用户
- 消除 `pkg/user/config.go` 和 `pkg/rbac/config.go` 中 DBConfig、SuperAdminConfig、PaginationConfig 的重复定义
- 不再使用的 `pkg/user/store/seed.go` 中的超管创建逻辑和 `pkg/rbac/store/seed.go` 中的超管角色分配逻辑移除

## Capabilities

### New Capabilities

- `cli-migrate`: `api-gateway migrate` 命令，统一执行所有模块的数据库迁移和种子数据初始化
- `cli-init-super-admin`: `api-gateway init-super-admin <username>` 命令，创建超级管理员用户并生成随机密码，输出到 stdout

### Modified Capabilities

- `user-rbac-config`: user 和 rbac 模块的配置结构去重、统一化
- `module-init`: user 和 rbac 模块的初始化流程不再自动执行迁移/种子

## Impact

- `pkg/user/config.go`: 移除 SuperAdminConfig 结构体和对应字段
- `pkg/rbac/config.go`: 移除 DBConfig、SuperAdminConfig 结构体和对应字段
- `pkg/user/user.go`: New() 移除 migrate/seed 调用
- `pkg/rbac/rbac.go`: New() 签名变更，接受 *gorm.DB 参数，移除 migrate/seed 和独立 DB 连接创建
- `pkg/user/store/seed.go`: 移除超级管理员用户创建逻辑，仅保留 __system__ 租户种子
- `pkg/rbac/store/seed.go`: 移除超级管理员角色分配逻辑，仅保留 system_admin/tenant_admin 角色创建
- `internal/api-gateway/gateway.go`: run() 适配新签名；注册 migrate 和 init-super-admin 子命令
- `configs/api-gateway.yaml.template`: 新增 user 配置段，rbac 段去重
- 新增 `internal/api-gateway/migrate.go` 和 `internal/api-gateway/initsuperadmin.go`
