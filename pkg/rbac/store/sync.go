package store

import (
	"context"

	"gorm.io/gorm"
)

type PolicySync struct {
	db *gorm.DB
}

func NewPolicySync(db *gorm.DB) *PolicySync {
	return &PolicySync{db: db}
}

type groupingRow struct {
	Username   string
	RoleCode   string
	TenantCode string
}

type policyRow struct {
	RoleCode   string
	TenantCode string
	Resource   string
	Action     string
}

// QueryGroupingPolicies returns all (username, roleCode, tenantCode) tuples for Casbin g policies.
func (s *PolicySync) QueryGroupingPolicies(ctx context.Context) ([][]string, error) {
	var rows []groupingRow
	err := s.db.WithContext(ctx).Raw(`
		SELECT u.username, r.code AS role_code, t.code AS tenant_code
		FROM user_roles ur
		JOIN users u ON u.id = ur.user_id
		JOIN roles r ON r.id = ur.role_id
		JOIN tenants t ON t.id = ur.tenant_id
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	result := make([][]string, len(rows))
	for i, r := range rows {
		result[i] = []string{r.Username, r.RoleCode, r.TenantCode}
	}
	return result, nil
}

// QueryPolicies returns all (roleCode, tenantCode, resource, action) tuples for Casbin p policies.
func (s *PolicySync) QueryPolicies(ctx context.Context) ([][]string, error) {
	var rows []policyRow
	err := s.db.WithContext(ctx).Raw(`
		SELECT r.code AS role_code, t.code AS tenant_code, p.resource, p.action
		FROM role_permissions rp
		JOIN roles r ON r.id = rp.role_id
		JOIN permissions p ON p.id = rp.permission_id
		JOIN tenants t ON t.id = r.tenant_id
	`).Scan(&rows).Error
	if err != nil {
		return nil, err
	}

	result := make([][]string, len(rows))
	for i, r := range rows {
		result[i] = []string{r.RoleCode, r.TenantCode, r.Resource, r.Action}
	}
	return result, nil
}
