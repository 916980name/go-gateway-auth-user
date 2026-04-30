package user

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
