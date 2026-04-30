## Why

The gateway currently delegates all user authentication to upstream backends — it only handles JWT signing after the upstream confirms identity. As the system grows, we need the gateway to authenticate users directly (password, SMS, OAuth) while keeping backward compatibility with upstream delegation. Additionally, user/tenant entities are currently embedded inside the RBAC module, but authentication is a more fundamental concern — this coupling needs to be resolved before building credential management on top.

## What Changes

- Extract user/tenant/tenant-domain entities from `pkg/rbac/` into a new `pkg/user/` module with its own store, handlers, and DB connection
- Remove `tenant_users` join table; add `tenant_id` to `users` table so each user belongs to exactly one tenant (model B: tenant-scoped users)
- Change username/email/phone uniqueness from global to tenant-scoped via partial unique indexes
- Create `user_credentials` table supporting multiple provider types per user (password, SMS, OAuth)
- Add `pkg/auth/` module with pluggable `CredentialProvider` interface and initial password provider implementation
- Add site-level `auth.mode` configuration: `upstream` (existing behavior) vs `gateway` (new direct authentication)
- Gateway-mode login endpoint: parses provider + identifier + credential, authenticates via the appropriate provider, then issues JWT using existing signing infrastructure
- **BREAKING**: RBAC admin API routes for user/tenant management move from `/admin/users`, `/admin/tenants` to being served by the `pkg/user/` module
- **BREAKING**: `tenant_users` table removed; existing data migrated to `users.tenant_id`

## Capabilities

### New Capabilities
- `user-module`: Standalone user/tenant entity management extracted from RBAC — models, repos, handlers, migrations, domain trie
- `auth-credentials`: Credential storage and pluggable authentication providers (password now; SMS and OAuth as future extensions)
- `gateway-login`: Gateway-mode direct authentication flow — site config, login/logout handlers, JWT issuance

### Modified Capabilities
- `rbac-data-model`: Users table gains `tenant_id`, `tenant_users` table removed, RBAC stores reference `pkg/user/store` instead of owning user/tenant repos

## Impact

- **Database**: Migration adds `users.tenant_id`, drops `tenant_users`, creates `user_credentials`, adjusts unique constraints
- **Code**: `pkg/rbac/` loses ~50% of its store and handler code (moved, not deleted); `pkg/rbac/rbac.go` initialization changes to accept external user/tenant repos
- **Config**: `Site` struct gains `auth` block with `mode` and `providers` fields; existing `inOutFilter` continues to work for `mode: upstream`
- **API**: Admin endpoints for user/tenant CRUD move out of RBAC admin handler into a separate handler served by `pkg/user/`
- **Dependencies**: `golang.org/x/crypto` added for bcrypt password hashing
