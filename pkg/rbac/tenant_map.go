package rbac

import (
	"context"
	"log/slog"
	"sync"
)

type tenantMap struct {
	mu   sync.RWMutex
	data map[string]string // hostname -> tenant code
}

func newTenantMap() *tenantMap {
	return &tenantMap{data: make(map[string]string)}
}

func (m *tenantMap) Get(hostname string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	code, ok := m.data[hostname]
	return code, ok
}

func (m *tenantMap) Replace(data map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = data
}

func (rc *RBAC) ResolveTenant(hostname string) (string, bool) {
	return rc.tenants.Get(hostname)
}

func (rc *RBAC) RefreshTenantMap(ctx context.Context) error {
	tenants, err := rc.tenantRepo.ListAllActive(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]string, len(tenants))
	for _, t := range tenants {
		m[t.Hostname] = t.Code
	}
	rc.tenants.Replace(m)
	slog.Info("tenant map refreshed", "count", len(m))
	return nil
}
