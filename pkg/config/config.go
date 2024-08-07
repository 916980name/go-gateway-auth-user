package config

import (
	"api-gateway/pkg/db/dbredis"
	"api-gateway/pkg/log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	ENV_PREFIX         = "GO_API_GATEWAY"
	defaultConfigName  = "api-gateway.yaml"
	recommendedHomeDir = ".api-gateway"
)

var (
	global    = &Config{}
	globalMux sync.RWMutex
)

func Global() *Config {
	globalMux.RLock()
	defer globalMux.RUnlock()

	cfg := &Config{}
	*cfg = *global
	return cfg
}

func Set(c *Config) {
	globalMux.Lock()
	defer globalMux.Unlock()

	global = c
}

func OnUpdate(f func(c *Config) error) error {
	globalMux.Lock()
	defer globalMux.Unlock()

	return f(global)
}

type ServerOptions struct {
	Addr    string
	Runmode string
	Port    string
}

// sign JWT, add blacklist
type LoginLogoutFilterConfig struct {
	LimiterName      string   `yaml:"limiterName,omitempty" json:"limiterName,omitempty"` // include blacklist block ips cache
	LoginPath        []string `yaml:"loginPath,omitempty" json:"loginPath,omitempty"`
	LogoutPath       string   `yaml:"logoutPath,omitempty" json:"logoutPath,omitempty"`
	RefreshTokenPath string   `yaml:"refreshTokenPath,omitempty" json:"refreshTokenPath,omitempty"`
	CookieEnabled    bool     `yaml:"cookieEnabled,omitempty" json:"cookieEnabled,omitempty"`
}

type RateLimiterFilterConfig struct {
	LimiterName string `yaml:"limiterName,omitempty" json:"limiterName,omitempty"`
	LimitType   string `yaml:"limitType,omitempty" json:"limitType,omitempty"`
}

type JWTConfig struct {
	// EncryptType   string `yaml:"encryptType,omitempty" json:"encryptType,omitempty"`
	// TokenSecret   string `yaml:"tokenSecret,omitempty" json:"tokenSecret,omitempty"`
	RSAPrivateKey string `yaml:"rsaPrivateKey,omitempty" json:"rsaPrivateKey,omitempty"`
	RSAPublicKey  string `yaml:"rsaPublicKey,omitempty" json:"rsaPublicKey,omitempty"`
}

type Site struct {
	HostName    string                   `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	JWTConfig   *JWTConfig               `yaml:"jwtConfig,omitempty" json:"jwtConfig,omitempty"`
	OnlineCache string                   `yaml:"onlineCache,omitempty" json:"onlineCache,omitempty"` // login success write token hash to cache indicate user online
	RateLimiter *RateLimiterFilterConfig `yaml:"rateLimiter,omitempty" json:"rateLimiter,omitempty"`
	InOutFilter *LoginLogoutFilterConfig `yaml:"inOutFilter,omitempty" json:"inOutFilter,omitempty"`
	Routes      []*RouteConfig           `yaml:"routes,omitempty" json:"routes,omitempty"`
}

type RouteConfig struct {
	Path        string                   `yaml:"path,omitempty" json:"path,omitempty"`
	Method      string                   `yaml:"method,omitempty" json:"method,omitempty"`
	Route       string                   `yaml:"route,omitempty" json:"route,omitempty"`
	Privilege   string                   `yaml:"privilege,omitempty" json:"privilege,omitempty"`
	RateLimiter *RateLimiterFilterConfig `yaml:"rateLimiter,omitempty" json:"rateLimiter,omitempty"`
}

type RateLimiterConfig struct {
	Name           string `yaml:"name,omitempty" json:"name,omitempty"`
	CacheName      string `yaml:"cacheName,omitempty" json:"cacheName,omitempty"`
	Max            int    `yaml:"max,omitempty" json:"max,omitempty"`
	RefillInterval int    `yaml:"refillInterval,omitempty" json:"refillInterval,omitempty"`
	RefillNumber   int    `yaml:"refillNumber,omitempty" json:"refillNumber,omitempty"`
}

type CacheConfig struct {
	Name               string `yaml:"name,omitempty" json:"name,omitempty"`
	Type               string `yaml:"type,omitempty" json:"type,omitempty"`
	Max                int    `yaml:"max,omitempty" json:"max,omitempty"`
	DefaulExpireMinute int    `yaml:"defaulExpireMinute,omitempty" json:"defaulExpireMinute,omitempty"`
}

type DBConfig struct {
	Redis *dbredis.RedisOptions `yaml:"redis,omitempty" json:"redis,omitempty"`
}

type Config struct {
	ServerOptions *ServerOptions       `yaml:"serverOptions,omitempty" json:"serverOptions,omitempty"`
	Db            *DBConfig            `yaml:"db,omitempty" json:"db,omitempty"`
	Sites         []*Site              `yaml:"sites,omitempty" json:"sites,omitempty"`
	RateLimiters  []*RateLimiterConfig `yaml:"rateLimiters,omitempty" json:"rateLimiters,omitempty"`
	Caches        []*CacheConfig       `yaml:"caches,omitempty" json:"caches,omitempty"`
}

func (c *Config) ReadConfig(cfgFile string) error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)
		viper.AddConfigPath(filepath.Join(home, recommendedHomeDir))
		viper.AddConfigPath(".")

		viper.SetConfigType("yaml")

		viper.SetConfigName(defaultConfigName)
	}

	viper.AutomaticEnv()
	viper.SetEnvPrefix(ENV_PREFIX)
	replacer := strings.NewReplacer(".", "_", "-", "_")
	viper.SetEnvKeyReplacer(replacer)

	if err := viper.ReadInConfig(); err != nil {
		log.Errorw("Error reading config file", "error", err)
	}

	if err := viper.ReadInConfig(); err == nil {
		log.Infow("Using config file:", "file", viper.ConfigFileUsed())
	}
	return viper.Unmarshal(c)
}
