package rbac

import "api-gateway/pkg/user"

type Config struct {
	DB        user.DBConfig `yaml:"db" json:"db"`
	AdminPath string        `yaml:"adminPath" json:"adminPath"`
}

func (c *Config) ApplyDefaults() {
	if c.AdminPath == "" {
		c.AdminPath = "/admin"
	}
}
