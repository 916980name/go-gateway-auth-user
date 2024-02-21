package gateway

import (
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
)

const (
	LIMITER_RefillInterval = 2
	LIMITER_RefillNumber   = 1
)

var (
	RateLimiterConfigs map[string]*config.RateLimiterConfig = make(map[string]*config.RateLimiterConfig)
)

func InitRateLimiterConfigs(rs []*config.RateLimiterConfig) error {
	for _, item := range rs {
		if item.Name == "" {
			log.Warnw("un-named rateLimiter config")
			continue
		}

		makeRateLimiterConfigValid(item)
		RateLimiterConfigs[item.Name] = item
	}
	return nil
}

func makeRateLimiterConfigValid(c *config.RateLimiterConfig) {
	if c.Max <= 0 {
		c.Max = CACHE_MAX
	}
	if c.RefillInterval <= 0 {
		c.RefillInterval = LIMITER_RefillInterval
	}
	if c.RefillNumber <= 0 {
		c.RefillNumber = LIMITER_RefillNumber
	}
}
