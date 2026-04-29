# Multi-Domain Tenant Resolution Design

## Problem

The current `tenants` table has a single `hostname` column with a UNIQUE constraint, enforcing a 1:1 mapping between tenant and domain. This is too restrictive — a tenant needs to bind multiple exact domains and wildcard domains (e.g., `*.example.com`).

## Requirements

1. A tenant can bind multiple domain patterns (exact or single-level wildcard `*.xxx.xxx`)
2. Exact domain match takes priority over wildcard match
3. Cross-tenant domain overlap is rejected; same-tenant overlap is allowed
4. The gateway routing layer (`mux.Router.Host`) is unaffected — tenant resolution only happens in RBAC middleware
5. Migration 001 has never been executed, so schema changes go directly into the existing migration file

## Approach: `tenant_domains` Table + Reverse Trie Matcher

### Data Model

**`tenants` table**: Remove the `hostname` column and its UNIQUE constraint.

**New `tenant_domains` table**:

```sql
CREATE TABLE IF NOT EXISTS tenant_domains (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pattern     VARCHAR(512) NOT NULL,
    is_wildcard BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(pattern)
);
CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id ON tenant_domains(tenant_id);
```

- `pattern`: Exact domain (`app.example.com`) or wildcard (`*.example.com`)
- `is_wildcard`: Redundant boolean for query convenience
- `UNIQUE(pattern)`: Prevents the same pattern from being bound to multiple tenants

### Reverse Trie Domain Matcher

Domains are split by `.` and reversed before insertion into a trie:

```
"app.example.com"   → ["com", "example", "app"]     → leaf stores tenantCode
"*.example.com"     → ["com", "example", "*"]        → "*" node stores tenantCode
"api.foo.org"       → ["org", "foo", "api"]          → leaf stores tenantCode
```

**Resolve algorithm** (looking up `sub.example.com`):

1. Reverse to `["com", "example", "sub"]`
2. Walk the trie: `com` → `example` → check exact child `sub` first
3. If exact match hits a terminal node → return its tenantCode
4. If exact match misses → check for `*` child node
5. If `*` child is terminal → return its tenantCode (wildcard match)
6. Otherwise → unknown tenant

Priority guarantee: exact children are always checked before `*` children.

**Go types**:

```go
type DomainEntry struct {
    Pattern    string // "app.example.com" or "*.example.com"
    TenantCode string
    IsWildcard bool
}

type trieNode struct {
    children map[string]*trieNode
    tenant   string // non-empty = terminal node, value is tenantCode
}

type DomainTrie struct {
    mu   sync.RWMutex
    root *trieNode
}

func (t *DomainTrie) Resolve(hostname string) (tenantCode string, ok bool)
func (t *DomainTrie) Replace(domains []DomainEntry)
```

`Replace` builds a new trie and atomically swaps the root pointer under write lock, matching the semantics of the current `tenantMap.Replace`.

**Port stripping**: `r.Host` may include a port (e.g., `app.example.com:8080`). `Resolve` strips the port before matching, consistent with the current `tenantMap` behavior where hostnames are stored without ports.

### Domain Overlap Validation

When adding a domain to a tenant, the application layer validates cross-tenant overlap:

| Adding | Check | Example |
|--------|-------|---------|
| Exact `app.example.com` | Does `*.example.com` exist for another tenant? | Other tenant owns `*.example.com` → reject |
| Wildcard `*.example.com` | Does any `xxx.example.com` exist for another tenant? | Other tenant owns `app.example.com` → reject |
| Any pattern | Does the exact pattern already exist? | UNIQUE constraint rejects |

Same-tenant overlap is allowed (e.g., a tenant can bind both `*.example.com` and `app.example.com`).

Implementation: `TenantDomainRepo.CheckOverlap(ctx, tenantID, pattern) error` performs SQL queries to detect cross-tenant conflicts before insert.

### Domain Management API

New REST endpoints under the existing admin router:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/tenants/{id}/domains` | List all domains for a tenant |
| `POST` | `/tenants/{id}/domains` | Add a domain to a tenant |
| `DELETE` | `/tenants/{id}/domains/{domainId}` | Remove a domain from a tenant |

On add/delete, `onTenantChange()` is triggered to refresh the Trie and reload Casbin policies.

No update endpoint — domains are added or removed, not modified.

### Request body for POST `/tenants/{id}/domains`:

```json
{
  "pattern": "*.example.com"
}
```

`is_wildcard` is derived from the pattern (starts with `*.`), not provided by the caller.

## Affected Code

| File | Change |
|------|--------|
| `pkg/rbac/store/migrations/001_init_schema.up.sql` | Remove `tenants.hostname`; add `tenant_domains` table |
| `pkg/rbac/store/models.go` | Remove `Hostname` from `Tenant`; add `TenantDomain` model |
| `pkg/rbac/store/tenant_repo.go` | Remove `GetByHostname`; add `TenantDomainRepo` with CRUD + overlap check + load-all |
| `pkg/rbac/store/seed.go` | Insert system tenant domain into `tenant_domains` instead of `tenants.hostname` |
| `pkg/rbac/tenant_map.go` → `pkg/rbac/domain_trie.go` | Replace `tenantMap` with `DomainTrie` |
| `pkg/rbac/rbac.go` | `RefreshTenantMap` loads from `TenantDomainRepo`, builds Trie |
| `pkg/rbac/middleware.go` | `ResolveTenant` calls `DomainTrie.Resolve` (interface stays the same) |
| `pkg/rbac/handler/tenant_handler.go` | Add `TenantDomainHandler` for domain CRUD endpoints |
| `pkg/rbac/admin.go` | Register domain routes |
| Test files | Update existing tests; add Trie unit tests and overlap validation tests |

**Unchanged**:
- Gateway routing (`internal/api-gateway/route.go`) — routes by hostname independently, not tenant-aware
- Casbin model and enforcer — input is still `(username, tenantCode, path, method)`
- Config file format — `sites` config unchanged

## Testing

**Unit tests**:
- `DomainTrie.Resolve`: exact match, wildcard match, exact-over-wildcard priority, no match, empty trie, `Replace` atomicity
- `TenantDomainRepo.CheckOverlap`: same-tenant no conflict, cross-tenant exact-vs-wildcard, cross-tenant wildcard-vs-exact

**Integration tests (update existing)**:
- `TestMiddlewareUnknownTenant`: adapt to new Trie initialization
- New: wildcard domain resolves to correct tenant
- New: exact domain takes priority over wildcard from another tenant binding
