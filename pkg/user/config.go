package user

type Config struct {
	DB         DBConfig         `yaml:"db" json:"db"`
	SuperAdmin SuperAdminConfig `yaml:"superAdmin" json:"superAdmin"`
	Pagination PaginationConfig `yaml:"pagination" json:"pagination"`
}

type DBConfig struct {
	DSN                    string `yaml:"dsn" json:"dsn"`
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
