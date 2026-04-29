# Multi-Domain Tenant Resolution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the 1:1 tenant-hostname mapping with a many-to-many `tenant_domains` table and a reverse trie matcher that supports exact domains and `*.example.com` wildcard patterns.

**Architecture:** A new `tenant_domains` table stores domain patterns per tenant. On startup (and on admin changes), all patterns are loaded into a `DomainTrie` — a reverse-label trie that resolves hostnames in O(depth) with exact-before-wildcard priority. The RBAC middleware calls `DomainTrie.Resolve` instead of the old flat map. A new admin API manages domain CRUD with cross-tenant overlap validation.

**Tech Stack:** Go 1.25, PostgreSQL (pgx v5), Casbin, net/http ServeMux

---

## File Structure

| File | Responsibility |
|------|---------------|
| `pkg/rbac/store/migrations/001_init_schema.up.sql` | (modify) Remove `tenants.hostname`, add `tenant_domains` table |
| `pkg/rbac/store/migrations/001_init_schema.down.sql` | (modify) Add `DROP TABLE IF EXISTS tenant_domains` |
| `pkg/rbac/store/models.go` | (modify) Remove `Hostname` from `Tenant`, add `TenantDomain` struct |
| `pkg/rbac/store/tenant_repo.go` | (modify) Remove `hostname` from all SQL queries and `Scan` calls |
| `pkg/rbac/store/tenant_domain_repo.go` | (create) `TenantDomainRepo` with CRUD, overlap check, load-all |
| `pkg/rbac/store/seed.go` | (modify) Insert system tenant domain into `tenant_domains` |
| `pkg/rbac/domain_trie.go` | (create) `DomainTrie` with `Resolve` and `Replace` |
| `pkg/rbac/domain_trie_test.go` | (create) Unit tests for trie |
| `pkg/rbac/tenant_map.go` | (delete) Replaced by `domain_trie.go` |
| `pkg/rbac/rbac.go` | (modify) Wire `DomainTrie` + `TenantDomainRepo` |
| `pkg/rbac/middleware.go` | (modify) Minimal — `ResolveTenant` moves to `domain_trie.go` |
| `pkg/rbac/middleware_test.go` | (modify) Update to use `DomainTrie` |
| `pkg/rbac/handler/tenant_handler.go` | (modify) Remove `hostname` from create/update requests |
| `pkg/rbac/handler/tenant_domain_handler.go` | (create) Domain CRUD handler |
| `pkg/rbac/admin.go` | (modify) Register domain routes |

---

### Task 1: DomainTrie — core data structure and tests

**Files:**
- Create: `pkg/rbac/domain_trie.go`
- Create: `pkg/rbac/domain_trie_test.go`

This is the pure-logic core with zero external dependencies. Build it first, test it thoroughly.

- [ ] **Step 1: Write the failing tests for DomainTrie**

Create `pkg/rbac/domain_trie_test.go`:

```go
package rbac

import (
	"testing"
)

func TestDomainTrieExactMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "app.example.com", TenantCode: "site-a"},
		{Pattern: "api.foo.org", TenantCode: "site-b"},
	})

	code, ok := trie.Resolve("app.example.com")
	if !ok || code != "site-a" {
		t.Errorf("expected site-a, got %s (found: %v)", code, ok)
	}

	code, ok = trie.Resolve("api.foo.org")
	if !ok || code != "site-b" {
		t.Errorf("expected site-b, got %s (found: %v)", code, ok)
	}
}

func TestDomainTrieWildcardMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "site-a", IsWildcard: true},
	})

	code, ok := trie.Resolve("anything.example.com")
	if !ok || code != "site-a" {
		t.Errorf("expected site-a, got %s (found: %v)", code, ok)
	}

	code, ok = trie.Resolve("other.example.com")
	if !ok || code != "site-a" {
		t.Errorf("expected site-a, got %s (found: %v)", code, ok)
	}
}

func TestDomainTrieExactOverWildcard(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "wildcard-tenant", IsWildcard: true},
		{Pattern: "app.example.com", TenantCode: "exact-tenant"},
	})

	code, ok := trie.Resolve("app.example.com")
	if !ok || code != "exact-tenant" {
		t.Errorf("exact should win: expected exact-tenant, got %s (found: %v)", code, ok)
	}

	code, ok = trie.Resolve("other.example.com")
	if !ok || code != "wildcard-tenant" {
		t.Errorf("wildcard should match: expected wildcard-tenant, got %s (found: %v)", code, ok)
	}
}

func TestDomainTrieNoMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "app.example.com", TenantCode: "site-a"},
	})

	_, ok := trie.Resolve("unknown.example.com")
	if ok {
		t.Error("expected no match for unknown domain")
	}
}

func TestDomainTrieEmptyTrie(t *testing.T) {
	trie := NewDomainTrie()

	_, ok := trie.Resolve("anything.com")
	if ok {
		t.Error("expected no match on empty trie")
	}
}

func TestDomainTriePortStripping(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "app.example.com", TenantCode: "site-a"},
	})

	code, ok := trie.Resolve("app.example.com:8080")
	if !ok || code != "site-a" {
		t.Errorf("should match after stripping port: expected site-a, got %s (found: %v)", code, ok)
	}
}

func TestDomainTrieWildcardDoesNotMatchDeeper(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "site-a", IsWildcard: true},
	})

	_, ok := trie.Resolve("a.b.example.com")
	if ok {
		t.Error("single-level wildcard should not match multi-level subdomain")
	}
}

func TestDomainTrieReplaceAtomicity(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "old.example.com", TenantCode: "old-tenant"},
	})

	trie.Replace([]DomainEntry{
		{Pattern: "new.example.com", TenantCode: "new-tenant"},
	})

	_, ok := trie.Resolve("old.example.com")
	if ok {
		t.Error("old entry should be gone after Replace")
	}

	code, ok := trie.Resolve("new.example.com")
	if !ok || code != "new-tenant" {
		t.Errorf("expected new-tenant, got %s (found: %v)", code, ok)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/lls/Research/go-gateway-auth-user && go test ./pkg/rbac/ -run TestDomainTrie -v`
Expected: compilation error — `NewDomainTrie`, `DomainEntry` undefined

- [ ] **Step 3: Implement DomainTrie**

Create `pkg/rbac/domain_trie.go`:

```go
package rbac

import (
	"net"
	"strings"
	"sync"
)

type DomainEntry struct {
	Pattern    string
	TenantCode string
	IsWildcard bool
}

type trieNode struct {
	children map[string]*trieNode
	tenant   string
}

type DomainTrie struct {
	mu   sync.RWMutex
	root *trieNode
}

func NewDomainTrie() *DomainTrie {
	return &DomainTrie{root: &trieNode{children: make(map[string]*trieNode)}}
}

func (t *DomainTrie) Replace(domains []DomainEntry) {
	root := &trieNode{children: make(map[string]*trieNode)}
	for _, d := range domains {
		pattern := d.Pattern
		if d.IsWildcard {
			pattern = strings.TrimPrefix(pattern, "*.")
		}
		labels := strings.Split(pattern, ".")
		reverseLabels(labels)

		node := root
		for _, label := range labels {
			child, ok := node.children[label]
			if !ok {
				child = &trieNode{children: make(map[string]*trieNode)}
				node.children[label] = child
			}
			node = child
		}
		if d.IsWildcard {
			wc, ok := node.children["*"]
			if !ok {
				wc = &trieNode{children: make(map[string]*trieNode)}
				node.children["*"] = wc
			}
			wc.tenant = d.TenantCode
		} else {
			node.tenant = d.TenantCode
		}
	}

	t.mu.Lock()
	t.root = root
	t.mu.Unlock()
}

func (t *DomainTrie) Resolve(hostname string) (string, bool) {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		host = hostname
	}

	labels := strings.Split(host, ".")
	reverseLabels(labels)

	t.mu.RLock()
	root := t.root
	t.mu.RUnlock()

	node := root
	for i, label := range labels {
		child, ok := node.children[label]
		if !ok {
			if wc, wcOk := node.children["*"]; wcOk && i == len(labels)-1 {
				if wc.tenant != "" {
					return wc.tenant, true
				}
			}
			return "", false
		}
		node = child
	}

	if node.tenant != "" {
		return node.tenant, true
	}
	return "", false
}

func reverseLabels(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /home/lls/Research/go-gateway-auth-user && go test ./pkg/rbac/ -run TestDomainTrie -v`
Expected: all 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add pkg/rbac/domain_trie.go pkg/rbac/domain_trie_test.go
git commit -m "feat(rbac): add DomainTrie with reverse-label trie for multi-domain tenant resolution"
```

---

### Task 2: Database schema — modify migration and down-migration

**Files:**
- Modify: `pkg/rbac/store/migrations/001_init_schema.up.sql`
- Modify: `pkg/rbac/store/migrations/001_init_schema.down.sql`

- [ ] **Step 1: Modify the up migration**

In `pkg/rbac/store/migrations/001_init_schema.up.sql`, make these changes:

1. Remove `hostname` line and its UNIQUE constraint from the `tenants` table (the line `hostname    VARCHAR(256) NOT NULL UNIQUE,`)
2. Add the `tenant_domains` table after the `tenants` table
3. Add index for `tenant_domains`

The `tenants` table should become:

```sql
CREATE TABLE IF NOT EXISTS tenants (
    id          BIGSERIAL PRIMARY KEY,
    uuid        UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    code        VARCHAR(64) NOT NULL UNIQUE,
    name        VARCHAR(256) NOT NULL,
    status      SMALLINT NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Add after the `tenants` table:

```sql
CREATE TABLE IF NOT EXISTS tenant_domains (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    pattern     VARCHAR(512) NOT NULL,
    is_wildcard BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(pattern)
);
```

Add to the index section at the bottom:

```sql
CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id ON tenant_domains(tenant_id);
```

- [ ] **Step 2: Modify the down migration**

In `pkg/rbac/store/migrations/001_init_schema.down.sql`, add `DROP TABLE IF EXISTS tenant_domains;` before the `DROP TABLE IF EXISTS tenants;` line. Order matters because `tenant_domains` references `tenants`.

The file should become:

```sql
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS tenant_users;
DROP TABLE IF EXISTS tenant_domains;
DROP TABLE IF EXISTS tenants;
DROP TABLE IF EXISTS users;
```

- [ ] **Step 3: Commit**

```bash
git add pkg/rbac/store/migrations/001_init_schema.up.sql pkg/rbac/store/migrations/001_init_schema.down.sql
git commit -m "feat(rbac): update schema — remove tenants.hostname, add tenant_domains table"
```

---

### Task 3: Update models and TenantRepo — remove hostname

**Files:**
- Modify: `pkg/rbac/store/models.go:21-30`
- Modify: `pkg/rbac/store/tenant_repo.go`

- [ ] **Step 1: Remove Hostname from Tenant model**

In `pkg/rbac/store/models.go`, change the `Tenant` struct from:

```go
type Tenant struct {
	ID        int64     `json:"-"`
	UUID      uuid.UUID `json:"uuid"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Hostname  string    `json:"hostname"`
	Status    int16     `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
```

to:

```go
type Tenant struct {
	ID        int64     `json:"-"`
	UUID      uuid.UUID `json:"uuid"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Status    int16     `json:"status"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
```

- [ ] **Step 2: Add TenantDomain model**

Add to `pkg/rbac/store/models.go`, after the `Tenant` struct:

```go
type TenantDomain struct {
	ID         int64     `json:"id"`
	TenantID   int64     `json:"-"`
	Pattern    string    `json:"pattern"`
	IsWildcard bool      `json:"isWildcard"`
	CreatedAt  time.Time `json:"createdAt"`
}
```

- [ ] **Step 3: Update TenantRepo — remove hostname from all SQL and Scan calls**

In `pkg/rbac/store/tenant_repo.go`, make these changes:

**`Create` method** — change:
```go
func (r *TenantRepo) Create(ctx context.Context, t *Tenant) error {
	return r.pool.QueryRow(ctx,
		`INSERT INTO tenants (code, name, hostname, status)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, uuid, created_at, updated_at`,
		t.Code, t.Name, t.Hostname, int16(1),
	).Scan(&t.ID, &t.UUID, &t.CreatedAt, &t.UpdatedAt)
}
```
to:
```go
func (r *TenantRepo) Create(ctx context.Context, t *Tenant) error {
	return r.pool.QueryRow(ctx,
		`INSERT INTO tenants (code, name, status)
		 VALUES ($1, $2, $3)
		 RETURNING id, uuid, created_at, updated_at`,
		t.Code, t.Name, int16(1),
	).Scan(&t.ID, &t.UUID, &t.CreatedAt, &t.UpdatedAt)
}
```

**`GetByUUID` method** — change:
```go
func (r *TenantRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE uuid = $1`, uid,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```
to:
```go
func (r *TenantRepo) GetByUUID(ctx context.Context, uid uuid.UUID) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, status, created_at, updated_at
		 FROM tenants WHERE uuid = $1`, uid,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```

**`List` method** — change the query and scan:
```go
rows, err := r.pool.Query(ctx,
	`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
	 FROM tenants WHERE status = 1 ORDER BY id LIMIT $1 OFFSET $2`,
	p.PageSize, offset,
)
```
to:
```go
rows, err := r.pool.Query(ctx,
	`SELECT id, uuid, code, name, status, created_at, updated_at
	 FROM tenants WHERE status = 1 ORDER BY id LIMIT $1 OFFSET $2`,
	p.PageSize, offset,
)
```

And change the scan inside the loop from:
```go
if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
```
to:
```go
if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
```

**`Update` method** — change:
```go
func (r *TenantRepo) Update(ctx context.Context, uid uuid.UUID, name, hostname *string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`UPDATE tenants SET
			name = COALESCE($2, name),
			hostname = COALESCE($3, hostname),
			updated_at = $4
		 WHERE uuid = $1
		 RETURNING id, uuid, code, name, hostname, status, created_at, updated_at`,
		uid, name, hostname, time.Now(),
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```
to:
```go
func (r *TenantRepo) Update(ctx context.Context, uid uuid.UUID, name *string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`UPDATE tenants SET
			name = COALESCE($2, name),
			updated_at = $3
		 WHERE uuid = $1
		 RETURNING id, uuid, code, name, status, created_at, updated_at`,
		uid, name, time.Now(),
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```

**Delete `GetByHostname` method entirely** (lines 97-107).

**`GetByCode` method** — change:
```go
func (r *TenantRepo) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
		 FROM tenants WHERE code = $1`, code,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```
to:
```go
func (r *TenantRepo) GetByCode(ctx context.Context, code string) (*Tenant, error) {
	t := &Tenant{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, uuid, code, name, status, created_at, updated_at
		 FROM tenants WHERE code = $1`, code,
	).Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return t, nil
}
```

**`ListAllActive` method** — change:
```go
rows, err := r.pool.Query(ctx,
	`SELECT id, uuid, code, name, hostname, status, created_at, updated_at
	 FROM tenants WHERE status = 1 ORDER BY id`)
```
to:
```go
rows, err := r.pool.Query(ctx,
	`SELECT id, uuid, code, name, status, created_at, updated_at
	 FROM tenants WHERE status = 1 ORDER BY id`)
```

And change the scan:
```go
if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Hostname, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
```
to:
```go
if err := rows.Scan(&t.ID, &t.UUID, &t.Code, &t.Name, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
```

- [ ] **Step 4: Verify compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/store/...`
Expected: may have compilation errors in callers (tenant_handler.go, seed.go) — that's fine, we'll fix those in later tasks.

- [ ] **Step 5: Commit**

```bash
git add pkg/rbac/store/models.go pkg/rbac/store/tenant_repo.go
git commit -m "refactor(rbac): remove hostname from Tenant model and repo, add TenantDomain model"
```

---

### Task 4: TenantDomainRepo — CRUD + overlap validation

**Files:**
- Create: `pkg/rbac/store/tenant_domain_repo.go`

- [ ] **Step 1: Create TenantDomainRepo**

Create `pkg/rbac/store/tenant_domain_repo.go`:

```go
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type TenantDomainRepo struct {
	pool *pgxpool.Pool
}

func NewTenantDomainRepo(pool *pgxpool.Pool) *TenantDomainRepo {
	return &TenantDomainRepo{pool: pool}
}

type DomainWithTenant struct {
	Pattern    string
	TenantCode string
	IsWildcard bool
}

func (r *TenantDomainRepo) Create(ctx context.Context, d *TenantDomain) error {
	d.IsWildcard = strings.HasPrefix(d.Pattern, "*.")
	return r.pool.QueryRow(ctx,
		`INSERT INTO tenant_domains (tenant_id, pattern, is_wildcard)
		 VALUES ($1, $2, $3)
		 RETURNING id, created_at`,
		d.TenantID, d.Pattern, d.IsWildcard,
	).Scan(&d.ID, &d.CreatedAt)
}

func (r *TenantDomainRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM tenant_domains WHERE id = $1`, id,
	)
	return err
}

func (r *TenantDomainRepo) ListByTenant(ctx context.Context, tenantID int64) ([]TenantDomain, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, tenant_id, pattern, is_wildcard, created_at
		 FROM tenant_domains WHERE tenant_id = $1 ORDER BY id`, tenantID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []TenantDomain
	for rows.Next() {
		var d TenantDomain
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Pattern, &d.IsWildcard, &d.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, d)
	}
	return items, nil
}

func (r *TenantDomainRepo) ListAllWithTenant(ctx context.Context) ([]DomainWithTenant, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT td.pattern, t.code, td.is_wildcard
		 FROM tenant_domains td
		 JOIN tenants t ON t.id = td.tenant_id
		 WHERE t.status = 1
		 ORDER BY td.id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []DomainWithTenant
	for rows.Next() {
		var d DomainWithTenant
		if err := rows.Scan(&d.Pattern, &d.TenantCode, &d.IsWildcard); err != nil {
			return nil, err
		}
		items = append(items, d)
	}
	return items, nil
}

func (r *TenantDomainRepo) CheckOverlap(ctx context.Context, tenantID int64, pattern string) error {
	isWildcard := strings.HasPrefix(pattern, "*.")

	if isWildcard {
		suffix := strings.TrimPrefix(pattern, "*.")
		likePattern := "%." + suffix
		var count int
		err := r.pool.QueryRow(ctx,
			`SELECT count(*) FROM tenant_domains
			 WHERE tenant_id != $1
			   AND is_wildcard = false
			   AND (pattern LIKE $2 OR pattern = $3)`,
			tenantID, likePattern, suffix,
		).Scan(&count)
		if err != nil {
			return fmt.Errorf("check overlap: %w", err)
		}
		if count > 0 {
			return fmt.Errorf("wildcard %s overlaps with %d existing exact domain(s) from other tenants", pattern, count)
		}
	} else {
		parts := strings.SplitN(pattern, ".", 2)
		if len(parts) == 2 {
			wildcardPattern := "*." + parts[1]
			var count int
			err := r.pool.QueryRow(ctx,
				`SELECT count(*) FROM tenant_domains
				 WHERE tenant_id != $1
				   AND pattern = $2`,
				tenantID, wildcardPattern,
			).Scan(&count)
			if err != nil {
				return fmt.Errorf("check overlap: %w", err)
			}
			if count > 0 {
				return fmt.Errorf("exact domain %s overlaps with wildcard %s from another tenant", pattern, wildcardPattern)
			}
		}
	}

	return nil
}

func (r *TenantDomainRepo) GetByID(ctx context.Context, id int64) (*TenantDomain, error) {
	d := &TenantDomain{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, tenant_id, pattern, is_wildcard, created_at
		 FROM tenant_domains WHERE id = $1`, id,
	).Scan(&d.ID, &d.TenantID, &d.Pattern, &d.IsWildcard, &d.CreatedAt)
	if err != nil {
		return nil, err
	}
	return d, nil
}
```

- [ ] **Step 2: Verify compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/store/...`
Expected: compiles cleanly

- [ ] **Step 3: Commit**

```bash
git add pkg/rbac/store/tenant_domain_repo.go
git commit -m "feat(rbac): add TenantDomainRepo with CRUD and cross-tenant overlap validation"
```

---

### Task 5: Update seed.go — system tenant domain

**Files:**
- Modify: `pkg/rbac/store/seed.go:10-18, 28-34`

- [ ] **Step 1: Update seed constants and SQL**

In `pkg/rbac/store/seed.go`:

1. Remove the `SystemTenantHostname` constant.
2. Update the tenant INSERT to remove `hostname`.
3. Add a new INSERT for the system tenant domain into `tenant_domains`.

Change:
```go
const (
	SystemTenantCode     = "__system__"
	SystemTenantName     = "System"
	SystemTenantHostname = "__system__"
	SystemAdminRoleCode  = "system_admin"
	SystemAdminRoleName  = "System Administrator"
	TenantAdminRoleCode  = "tenant_admin"
	TenantAdminRoleName  = "Tenant Administrator"
)
```
to:
```go
const (
	SystemTenantCode        = "__system__"
	SystemTenantName        = "System"
	SystemTenantDomain      = "__system__"
	SystemAdminRoleCode     = "system_admin"
	SystemAdminRoleName     = "System Administrator"
	TenantAdminRoleCode     = "tenant_admin"
	TenantAdminRoleName     = "Tenant Administrator"
)
```

Change the tenant upsert from:
```go
	err = tx.QueryRow(ctx,
		`INSERT INTO tenants (code, name, hostname, status)
		 VALUES ($1, $2, $3, 1)
		 ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
		 RETURNING id`,
		SystemTenantCode, SystemTenantName, SystemTenantHostname,
	).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("upsert system tenant: %w", err)
	}
```
to:
```go
	err = tx.QueryRow(ctx,
		`INSERT INTO tenants (code, name, status)
		 VALUES ($1, $2, 1)
		 ON CONFLICT (code) DO UPDATE SET code = EXCLUDED.code
		 RETURNING id`,
		SystemTenantCode, SystemTenantName,
	).Scan(&tenantID)
	if err != nil {
		return fmt.Errorf("upsert system tenant: %w", err)
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO tenant_domains (tenant_id, pattern, is_wildcard)
		 VALUES ($1, $2, false)
		 ON CONFLICT (pattern) DO NOTHING`,
		tenantID, SystemTenantDomain,
	)
	if err != nil {
		return fmt.Errorf("upsert system tenant domain: %w", err)
	}
```

- [ ] **Step 2: Verify compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/store/...`
Expected: compiles cleanly

- [ ] **Step 3: Commit**

```bash
git add pkg/rbac/store/seed.go
git commit -m "refactor(rbac): update seed to use tenant_domains instead of tenants.hostname"
```

---

### Task 6: Wire DomainTrie into RBAC core — replace tenantMap

**Files:**
- Modify: `pkg/rbac/rbac.go:12-20, 52-64`
- Delete: `pkg/rbac/tenant_map.go`
- Modify: `pkg/rbac/middleware.go` (remove `ResolveTenant` reference — it moves to `domain_trie.go`)

- [ ] **Step 1: Update RBAC struct and New()**

In `pkg/rbac/rbac.go`, change:

```go
type RBAC struct {
	cfg        Config
	enforcer   *Enforcer
	tenants    *tenantMap
	tenantRepo *store.TenantRepo
	userRepo   *store.UserRepo
	roleRepo   *store.RoleRepo
	permRepo   *store.PermissionRepo
}
```
to:
```go
type RBAC struct {
	cfg            Config
	enforcer       *Enforcer
	tenants        *DomainTrie
	tenantRepo     *store.TenantRepo
	domainRepo     *store.TenantDomainRepo
	userRepo       *store.UserRepo
	roleRepo       *store.RoleRepo
	permRepo       *store.PermissionRepo
}
```

In the `New` function, change:

```go
	rc := &RBAC{
		cfg:        cfg,
		enforcer:   enforcer,
		tenants:    newTenantMap(),
		tenantRepo: store.NewTenantRepo(pool),
		userRepo:   store.NewUserRepo(pool),
		roleRepo:   store.NewRoleRepo(pool),
		permRepo:   store.NewPermissionRepo(pool),
	}
```
to:
```go
	rc := &RBAC{
		cfg:        cfg,
		enforcer:   enforcer,
		tenants:    NewDomainTrie(),
		tenantRepo: store.NewTenantRepo(pool),
		domainRepo: store.NewTenantDomainRepo(pool),
		userRepo:   store.NewUserRepo(pool),
		roleRepo:   store.NewRoleRepo(pool),
		permRepo:   store.NewPermissionRepo(pool),
	}
```

- [ ] **Step 2: Move ResolveTenant and RefreshTenantMap into domain_trie.go**

Append to `pkg/rbac/domain_trie.go`:

```go
func (rc *RBAC) ResolveTenant(hostname string) (string, bool) {
	return rc.tenants.Resolve(hostname)
}

func (rc *RBAC) RefreshTenantMap(ctx context.Context) error {
	domains, err := rc.domainRepo.ListAllWithTenant(ctx)
	if err != nil {
		return err
	}
	entries := make([]DomainEntry, len(domains))
	for i, d := range domains {
		entries[i] = DomainEntry{
			Pattern:    d.Pattern,
			TenantCode: d.TenantCode,
			IsWildcard: d.IsWildcard,
		}
	}
	rc.tenants.Replace(entries)
	slog.Info("tenant domain trie refreshed", "count", len(entries))
	return nil
}
```

Add `"context"` and `"log/slog"` to the import block in `domain_trie.go`.

- [ ] **Step 3: Delete tenant_map.go**

Delete `pkg/rbac/tenant_map.go` entirely.

- [ ] **Step 4: Verify compilation of the full rbac package**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/...`
Expected: may fail on tenant_handler.go (hostname references) — that's expected, fixed in Task 7.

- [ ] **Step 5: Commit**

```bash
git rm pkg/rbac/tenant_map.go
git add pkg/rbac/rbac.go pkg/rbac/domain_trie.go
git commit -m "refactor(rbac): replace tenantMap with DomainTrie, wire TenantDomainRepo"
```

---

### Task 7: Update TenantHandler — remove hostname from create/update

**Files:**
- Modify: `pkg/rbac/handler/tenant_handler.go`

- [ ] **Step 1: Update request types and handler methods**

In `pkg/rbac/handler/tenant_handler.go`:

Change `createTenantRequest`:
```go
type createTenantRequest struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}
```
to:
```go
type createTenantRequest struct {
	Code string `json:"code"`
	Name string `json:"name"`
}
```

Change `updateTenantRequest`:
```go
type updateTenantRequest struct {
	Name     *string `json:"name"`
	Hostname *string `json:"hostname"`
}
```
to:
```go
type updateTenantRequest struct {
	Name *string `json:"name"`
}
```

Change the `Create` method validation and object construction:
```go
	if req.Code == "" || req.Name == "" || req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "code, name, and hostname are required")
		return
	}
	t := &store.Tenant{Code: req.Code, Name: req.Name, Hostname: req.Hostname}
```
to:
```go
	if req.Code == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "code and name are required")
		return
	}
	t := &store.Tenant{Code: req.Code, Name: req.Name}
```

Change the `Update` method call:
```go
	t, err := h.repo.Update(r.Context(), uid, req.Name, req.Hostname)
```
to:
```go
	t, err := h.repo.Update(r.Context(), uid, req.Name)
```

- [ ] **Step 2: Verify compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/...`
Expected: compiles cleanly (or very close — any remaining issues will be in middleware_test.go)

- [ ] **Step 3: Commit**

```bash
git add pkg/rbac/handler/tenant_handler.go
git commit -m "refactor(rbac): remove hostname from tenant create/update API"
```

---

### Task 8: TenantDomainHandler — domain CRUD API

**Files:**
- Create: `pkg/rbac/handler/tenant_domain_handler.go`
- Modify: `pkg/rbac/admin.go`

- [ ] **Step 1: Create TenantDomainHandler**

Create `pkg/rbac/handler/tenant_domain_handler.go`:

```go
package handler

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
)

type TenantDomainHandler struct {
	domainRepo *store.TenantDomainRepo
	tenantRepo *store.TenantRepo
	onChange   func()
}

func NewTenantDomainHandler(domainRepo *store.TenantDomainRepo, tenantRepo *store.TenantRepo, onChange func()) *TenantDomainHandler {
	return &TenantDomainHandler{domainRepo: domainRepo, tenantRepo: tenantRepo, onChange: onChange}
}

var domainPattern = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

type createDomainRequest struct {
	Pattern string `json:"pattern"`
}

func (h *TenantDomainHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}
	domains, err := h.domainRepo.ListByTenant(r.Context(), tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if domains == nil {
		domains = []store.TenantDomain{}
	}
	writeJSON(w, http.StatusOK, domains)
}

func (h *TenantDomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	var req createDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	req.Pattern = strings.ToLower(strings.TrimSpace(req.Pattern))
	if !domainPattern.MatchString(req.Pattern) {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid domain pattern: must be exact domain or *.domain.tld")
		return
	}

	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}

	if err := h.domainRepo.CheckOverlap(r.Context(), tenant.ID, req.Pattern); err != nil {
		writeError(w, http.StatusConflict, "DOMAIN_OVERLAP", err.Error())
		return
	}

	d := &store.TenantDomain{TenantID: tenant.ID, Pattern: req.Pattern}
	if err := h.domainRepo.Create(r.Context(), d); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "DOMAIN_EXISTS", "domain pattern already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	writeJSON(w, http.StatusCreated, d)
}

func (h *TenantDomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(r.PathValue("domainId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid domain id")
		return
	}
	if err := h.domainRepo.Delete(r.Context(), domainID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	w.WriteHeader(http.StatusNoContent)
}
```

- [ ] **Step 2: Register domain routes in admin.go**

In `pkg/rbac/admin.go`, add the domain handler construction and routes.

After the `th` line:
```go
	th := handler.NewTenantHandler(rc.tenantRepo, pgCfg, func() { rc.onTenantChange() })
```
add:
```go
	dh := handler.NewTenantDomainHandler(rc.domainRepo, rc.tenantRepo, func() { rc.onTenantChange() })
```

After the existing tenant routes block (`DELETE /tenants/{id}`), add:
```go
	// Tenant domain management
	mux.HandleFunc("GET /tenants/{id}/domains", dh.List)
	mux.HandleFunc("POST /tenants/{id}/domains", dh.Create)
	mux.HandleFunc("DELETE /tenants/{id}/domains/{domainId}", dh.Delete)
```

- [ ] **Step 3: Verify compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./pkg/rbac/...`
Expected: compiles cleanly

- [ ] **Step 4: Commit**

```bash
git add pkg/rbac/handler/tenant_domain_handler.go pkg/rbac/admin.go
git commit -m "feat(rbac): add tenant domain CRUD API with overlap validation"
```

---

### Task 9: Update existing tests

**Files:**
- Modify: `pkg/rbac/middleware_test.go`

- [ ] **Step 1: Update middleware tests to use DomainTrie**

In `pkg/rbac/middleware_test.go`:

Change `TestMiddlewareMissingUsername`:
```go
	rc := &RBAC{
		tenants: newTenantMap(),
	}
```
to:
```go
	rc := &RBAC{
		tenants: NewDomainTrie(),
	}
```

Change `TestMiddlewareUnknownTenant`:
```go
	rc := &RBAC{
		tenants: newTenantMap(),
	}
```
to:
```go
	rc := &RBAC{
		tenants: NewDomainTrie(),
	}
```

Delete `TestTenantMapOperations` entirely (lines 54-82) — it tests the old `tenantMap` which no longer exists. The `DomainTrie` tests in `domain_trie_test.go` replace it.

- [ ] **Step 2: Run all tests**

Run: `cd /home/lls/Research/go-gateway-auth-user && go test ./pkg/rbac/... -v`
Expected: all tests PASS

- [ ] **Step 3: Commit**

```bash
git add pkg/rbac/middleware_test.go
git commit -m "test(rbac): update middleware tests for DomainTrie, remove old tenantMap tests"
```

---

### Task 10: Final compilation check and full test run

**Files:** none (verification only)

- [ ] **Step 1: Full package compilation**

Run: `cd /home/lls/Research/go-gateway-auth-user && go build ./...`
Expected: compiles cleanly with zero errors

- [ ] **Step 2: Run all tests in the project**

Run: `cd /home/lls/Research/go-gateway-auth-user && go test ./... -v`
Expected: all tests PASS

- [ ] **Step 3: Run go vet**

Run: `cd /home/lls/Research/go-gateway-auth-user && go vet ./...`
Expected: no issues
