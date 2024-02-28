package dbredis

import "github.com/spf13/viper"

var (
	// should set env: GO_API_GATEWAY_REDIS_HOST, because we have setting viper autoenv prefix
	ENV_REDIS_HOST = "REDIS_HOST"
)

type RedisOptions struct {
	ConnectionString string `yaml:"connectionString,omitempty" json:"connectionString,omitempty"`
}

func NewRedisOptions() *RedisOptions {
	return &RedisOptions{
		ConnectionString: "redis://localhost:6379",
	}
}

func ReadRedisOptions(cs string) *RedisOptions {
	connStr := viper.GetString(ENV_REDIS_HOST)
	if connStr == "" {
		connStr = cs
	}

	options := NewRedisOptions()
	options.ConnectionString = connStr
	return options
}
