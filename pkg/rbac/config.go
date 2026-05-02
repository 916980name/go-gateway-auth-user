package rbac

import (
	"net/url"
	"strings"
)

type Config struct {
	Enabled  bool       `yaml:"enabled" json:"enabled"`
	DB       DBConfig   `yaml:"db" json:"db"`
	AdminPath string    `yaml:"adminPath" json:"adminPath"`
	SuperAdmin SuperAdminConfig `yaml:"superAdmin" json:"superAdmin"`
	Pagination PaginationConfig `yaml:"pagination" json:"pagination"`
}

type DBConfig struct {
	Driver                 string `yaml:"driver" json:"driver"`
	DSN                    string `yaml:"dsn" json:"dsn"`
	// Casbin table schema (adapter does not use DSN search_path); default: first DSN search_path entry or public.
	Schema                 string `yaml:"schema" json:"schema"`
	MaxOpenConns           int    `yaml:"maxOpenConns" json:"maxOpenConns"`
	MaxIdleConns           int    `yaml:"maxIdleConns" json:"maxIdleConns"`
	ConnMaxLifetimeMinutes int    `yaml:"connMaxLifetimeMinutes" json:"connMaxLifetimeMinutes"`
}

type SuperAdminConfig struct {
	Username string `yaml:"username" json:"username"`
}

type PaginationConfig struct {
	DefaultPageSize int `yaml:"defaultPageSize" json:"defaultPageSize"`
	MaxPageSize     int `yaml:"maxPageSize" json:"maxPageSize"`
}

func (c *Config) ApplyDefaults() {
	if c.AdminPath == "" {
		c.AdminPath = "/admin"
	}
	if c.DB.Driver == "" {
		c.DB.Driver = "postgres"
	}
	if c.DB.Schema == "" {
		if s := firstSchemaFromPostgresDSN(c.DB.DSN); s != "" {
			c.DB.Schema = s
		} else {
			c.DB.Schema = "public"
		}
	}
	if c.DB.MaxOpenConns <= 0 {
		c.DB.MaxOpenConns = 25
	}
	if c.DB.MaxIdleConns <= 0 {
		c.DB.MaxIdleConns = 5
	}
	if c.DB.ConnMaxLifetimeMinutes <= 0 {
		c.DB.ConnMaxLifetimeMinutes = 30
	}
	if c.Pagination.DefaultPageSize <= 0 {
		c.Pagination.DefaultPageSize = 20
	}
	if c.Pagination.MaxPageSize <= 0 {
		c.Pagination.MaxPageSize = 100
	}
}

// firstSchemaFromPostgresDSN returns the first schema in search_path from a postgres URL or keyword DSN.
func firstSchemaFromPostgresDSN(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return ""
	}
	if u, err := url.Parse(dsn); err == nil && u.Scheme != "" &&
		(u.Scheme == "postgres" || u.Scheme == "postgresql") {
		if q := strings.TrimSpace(u.Query().Get("search_path")); q != "" {
			return strings.TrimSpace(strings.Split(q, ",")[0])
		}
	}
	for _, tok := range strings.Fields(dsn) {
		const p = "search_path="
		if strings.HasPrefix(tok, p) {
			v := strings.Trim(strings.TrimPrefix(tok, p), `"'`)
			if v != "" {
				return strings.TrimSpace(strings.Split(v, ",")[0])
			}
		}
	}
	return ""
}
