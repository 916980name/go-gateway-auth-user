package rbac

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	pgadapter "github.com/cychiuae/casbin-pg-adapter"
	_ "github.com/lib/pq"
)

type Enforcer struct {
	enforcer *casbin.Enforcer
	mu       sync.RWMutex
}

func NewEnforcer(dsn, schema string) (*Enforcer, error) {
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		return nil, fmt.Errorf("parse casbin model: %w", err)
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sql db for casbin: %w", err)
	}

	adapter, err := pgadapter.NewAdapterWithDBSchema(db, schema, "casbin_rules")
	if err != nil {
		return nil, fmt.Errorf("create casbin pg adapter: %w", err)
	}

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("create casbin enforcer: %w", err)
	}

	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("load casbin policy: %w", err)
	}

	return &Enforcer{enforcer: e}, nil
}

func (e *Enforcer) Enforce(sub, dom, obj, act string) (bool, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.enforcer.Enforce(sub, dom, obj, act)
}

func (e *Enforcer) LoadPolicy() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.enforcer.LoadPolicy(); err != nil {
		slog.Error("reload casbin policy failed", "error", err)
		return err
	}
	return nil
}

func (e *Enforcer) AddRoleForUserInDomain(user, role, domain string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.enforcer.AddGroupingPolicy(user, role, domain)
	return err
}

func (e *Enforcer) RemoveRoleForUserInDomain(user, role, domain string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.enforcer.RemoveGroupingPolicy(user, role, domain)
	return err
}

func (e *Enforcer) AddPolicy(role, domain, resource, action string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.enforcer.AddPolicy(role, domain, resource, action)
	return err
}

func (e *Enforcer) RemovePolicy(role, domain, resource, action string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, err := e.enforcer.RemovePolicy(role, domain, resource, action)
	return err
}

func (e *Enforcer) RebuildPolicies(grouping, policies [][]string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.enforcer.ClearPolicy()
	if len(grouping) > 0 {
		if _, err := e.enforcer.AddGroupingPolicies(grouping); err != nil {
			return err
		}
	}
	if len(policies) > 0 {
		if _, err := e.enforcer.AddPolicies(policies); err != nil {
			return err
		}
	}
	return e.enforcer.SavePolicy()
}
