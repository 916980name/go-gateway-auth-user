package user

import (
	"net"
	"strings"
	"sync"
)

type TenantInfo struct {
	Code string
	UUID string
}

type DomainEntry struct {
	Pattern    string
	TenantCode string
	TenantUUID string
	IsWildcard bool
}

type trieNode struct {
	children map[string]*trieNode
	tenant   *TenantInfo
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
		info := &TenantInfo{Code: d.TenantCode, UUID: d.TenantUUID}
		if d.IsWildcard {
			wc, ok := node.children["*"]
			if !ok {
				wc = &trieNode{children: make(map[string]*trieNode)}
				node.children["*"] = wc
			}
			wc.tenant = info
		} else {
			node.tenant = info
		}
	}

	t.mu.Lock()
	t.root = root
	t.mu.Unlock()
}

func (t *DomainTrie) Resolve(hostname string) (*TenantInfo, bool) {
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
				if wc.tenant != nil {
					return wc.tenant, true
				}
			}
			return nil, false
		}
		node = child
	}

	if node.tenant != nil {
		return node.tenant, true
	}
	return nil, false
}

func reverseLabels(s []string) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
