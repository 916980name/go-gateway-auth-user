package rbac

import (
	"context"
	"log/slog"
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
