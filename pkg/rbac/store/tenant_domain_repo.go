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
