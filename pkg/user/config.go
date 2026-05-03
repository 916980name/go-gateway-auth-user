package user

type Config struct {
	DB DBConfig `yaml:"db" json:"db"`
}

type DBConfig struct {
	DSN                    string `yaml:"dsn" json:"dsn"`
	MaxOpenConns           int    `yaml:"maxOpenConns" json:"maxOpenConns"`
	MaxIdleConns           int    `yaml:"maxIdleConns" json:"maxIdleConns"`
	ConnMaxLifetimeMinutes int    `yaml:"connMaxLifetimeMinutes" json:"connMaxLifetimeMinutes"`
}

func (c *DBConfig) ApplyDefaults() {
	if c.MaxOpenConns <= 0 {
		c.MaxOpenConns = 25
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 5
	}
	if c.ConnMaxLifetimeMinutes <= 0 {
		c.ConnMaxLifetimeMinutes = 30
	}
}
