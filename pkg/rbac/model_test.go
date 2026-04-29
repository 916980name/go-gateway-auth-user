package rbac

import (
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

func newTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		t.Fatalf("parse model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("create enforcer: %v", err)
	}
	return e
}

func TestCasbinModelBasicEnforce(t *testing.T) {
	e := newTestEnforcer(t)

	// alice has admin role in site-a
	e.AddGroupingPolicy("alice", "admin", "site-a")
	// admin in site-a can GET /api/users/*
	e.AddPolicy("admin", "site-a", "/api/users/*", "GET")
	e.AddPolicy("admin", "site-a", "/api/users/*", "POST")

	tests := []struct {
		sub, dom, obj, act string
		want               bool
	}{
		{"alice", "site-a", "/api/users/123", "GET", true},
		{"alice", "site-a", "/api/users/123", "POST", true},
		{"alice", "site-a", "/api/users/123", "DELETE", false},
		{"alice", "site-b", "/api/users/123", "GET", false},
		{"bob", "site-a", "/api/users/123", "GET", false},
	}

	for _, tt := range tests {
		got, err := e.Enforce(tt.sub, tt.dom, tt.obj, tt.act)
		if err != nil {
			t.Errorf("enforce(%s,%s,%s,%s): %v", tt.sub, tt.dom, tt.obj, tt.act, err)
			continue
		}
		if got != tt.want {
			t.Errorf("enforce(%s,%s,%s,%s) = %v, want %v", tt.sub, tt.dom, tt.obj, tt.act, got, tt.want)
		}
	}
}

func TestCasbinModelDomainIsolation(t *testing.T) {
	e := newTestEnforcer(t)

	e.AddGroupingPolicy("alice", "admin", "site-a")
	e.AddGroupingPolicy("alice", "viewer", "site-b")
	e.AddPolicy("admin", "site-a", "/api/users/*", "GET")
	e.AddPolicy("admin", "site-a", "/api/users/*", "POST")
	e.AddPolicy("viewer", "site-b", "/api/users/*", "GET")

	// alice can POST in site-a but not in site-b
	got, _ := e.Enforce("alice", "site-a", "/api/users/1", "POST")
	if !got {
		t.Error("alice should POST in site-a")
	}
	got, _ = e.Enforce("alice", "site-b", "/api/users/1", "POST")
	if got {
		t.Error("alice should NOT POST in site-b")
	}

	// alice can GET in both
	got, _ = e.Enforce("alice", "site-a", "/api/users/1", "GET")
	if !got {
		t.Error("alice should GET in site-a")
	}
	got, _ = e.Enforce("alice", "site-b", "/api/users/1", "GET")
	if !got {
		t.Error("alice should GET in site-b")
	}
}

func TestCasbinModelKeyMatch2(t *testing.T) {
	e := newTestEnforcer(t)

	e.AddGroupingPolicy("alice", "admin", "site-a")
	e.AddPolicy("admin", "site-a", "/api/users/:id", "GET")

	got, _ := e.Enforce("alice", "site-a", "/api/users/abc-123", "GET")
	if !got {
		t.Error("keyMatch2 should match /api/users/abc-123 against /api/users/:id")
	}

	got, _ = e.Enforce("alice", "site-a", "/api/users/abc-123/extra", "GET")
	if got {
		t.Error("keyMatch2 should NOT match /api/users/abc-123/extra against /api/users/:id")
	}
}

func TestCasbinModelRoleInheritance(t *testing.T) {
	e := newTestEnforcer(t)

	e.AddGroupingPolicy("alice", "admin", "site-a")
	e.AddPolicy("admin", "site-a", "/api/*", "GET")
	e.AddPolicy("admin", "site-a", "/api/*", "POST")

	// Wildcard resource matching
	got, _ := e.Enforce("alice", "site-a", "/api/anything", "GET")
	if !got {
		t.Error("wildcard should match /api/anything")
	}
}
