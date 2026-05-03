package rbac

type Config struct {
	AdminPath  string           `yaml:"adminPath" json:"adminPath"`
	Pagination PaginationConfig `yaml:"pagination" json:"pagination"`
}

type PaginationConfig struct {
	DefaultPageSize int `yaml:"defaultPageSize" json:"defaultPageSize"`
	MaxPageSize     int `yaml:"maxPageSize" json:"maxPageSize"`
}

func (c *Config) ApplyDefaults() {
	if c.AdminPath == "" {
		c.AdminPath = "/admin"
	}
	if c.Pagination.DefaultPageSize <= 0 {
		c.Pagination.DefaultPageSize = 20
	}
	if c.Pagination.MaxPageSize <= 0 {
		c.Pagination.MaxPageSize = 100
	}
}
