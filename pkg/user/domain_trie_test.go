package user

import (
	"testing"
)

func TestDomainTrieExactMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "app.example.com", TenantCode: "site-a", TenantUUID: "uuid-a"},
		{Pattern: "api.foo.org", TenantCode: "site-b", TenantUUID: "uuid-b"},
	})

	info, ok := trie.Resolve("app.example.com")
	if !ok || info.Code != "site-a" || info.UUID != "uuid-a" {
		t.Errorf("expected site-a/uuid-a, got %+v (found: %v)", info, ok)
	}

	info, ok = trie.Resolve("api.foo.org")
	if !ok || info.Code != "site-b" || info.UUID != "uuid-b" {
		t.Errorf("expected site-b/uuid-b, got %+v (found: %v)", info, ok)
	}
}

func TestDomainTrieWildcardMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "site-a", TenantUUID: "uuid-wc", IsWildcard: true},
	})

	info, ok := trie.Resolve("anything.example.com")
	if !ok || info.Code != "site-a" || info.UUID != "uuid-wc" {
		t.Errorf("expected site-a/uuid-wc, got %+v (found: %v)", info, ok)
	}

	info, ok = trie.Resolve("other.example.com")
	if !ok || info.Code != "site-a" || info.UUID != "uuid-wc" {
		t.Errorf("expected site-a/uuid-wc, got %+v (found: %v)", info, ok)
	}
}

func TestDomainTrieExactOverWildcard(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "wildcard-tenant", TenantUUID: "uuid-wc", IsWildcard: true},
		{Pattern: "app.example.com", TenantCode: "exact-tenant", TenantUUID: "uuid-exact"},
	})

	info, ok := trie.Resolve("app.example.com")
	if !ok || info.Code != "exact-tenant" {
		t.Errorf("exact should win: expected exact-tenant, got %+v (found: %v)", info, ok)
	}

	info, ok = trie.Resolve("other.example.com")
	if !ok || info.Code != "wildcard-tenant" {
		t.Errorf("wildcard should match: expected wildcard-tenant, got %+v (found: %v)", info, ok)
	}
}

func TestDomainTrieNoMatch(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "app.example.com", TenantCode: "site-a", TenantUUID: "uuid-a"},
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
		{Pattern: "app.example.com", TenantCode: "site-a", TenantUUID: "uuid-a"},
	})

	info, ok := trie.Resolve("app.example.com:8080")
	if !ok || info.Code != "site-a" || info.UUID != "uuid-a" {
		t.Errorf("should match after stripping port: expected site-a/uuid-a, got %+v (found: %v)", info, ok)
	}
}

func TestDomainTrieWildcardDoesNotMatchDeeper(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "*.example.com", TenantCode: "site-a", TenantUUID: "uuid-wc", IsWildcard: true},
	})

	_, ok := trie.Resolve("a.b.example.com")
	if ok {
		t.Error("single-level wildcard should not match multi-level subdomain")
	}
}

func TestDomainTrieReplaceAtomicity(t *testing.T) {
	trie := NewDomainTrie()
	trie.Replace([]DomainEntry{
		{Pattern: "old.example.com", TenantCode: "old-tenant", TenantUUID: "uuid-old"},
	})

	trie.Replace([]DomainEntry{
		{Pattern: "new.example.com", TenantCode: "new-tenant", TenantUUID: "uuid-new"},
	})

	_, ok := trie.Resolve("old.example.com")
	if ok {
		t.Error("old entry should be gone after Replace")
	}

	info, ok := trie.Resolve("new.example.com")
	if !ok || info.Code != "new-tenant" || info.UUID != "uuid-new" {
		t.Errorf("expected new-tenant/uuid-new, got %+v (found: %v)", info, ok)
	}
}
