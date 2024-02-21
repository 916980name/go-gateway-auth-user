package gateway

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"fmt"
	"time"
)

const (
	CACHE_TYPE_MEM       = "mem"
	CACHE_TYPE_REDIS     = "redis"
	CACHE_MAX            = 10000
	CACHE_DEFAULT_EXPIRE = 30
)

var (
	Caches map[string]*cache.CacheOper = make(map[string]*cache.CacheOper)
)

func InitCaches(cs []*config.CacheConfig) error {
	for _, item := range cs {
		if item.Name == "" {
			log.Warnw("un-named cache config")
			continue
		}
		makeCacheConfigValid(item)
		c, e := initByType(item)
		if e != nil {
			log.Warnw(e.Error())
			continue
		}
		Caches[item.Name] = c
	}

	return nil
}

func initByType(cconf *config.CacheConfig) (*cache.CacheOper, error) {
	switch cconf.Type {
	case CACHE_TYPE_MEM:
		c, e := cache.NewMemCache(cconf.Max, time.Duration(cconf.DefaulExpireMinute)*time.Minute)
		return &c, e
	case CACHE_TYPE_REDIS:
		return nil, fmt.Errorf("TODO type cache config: %s", cconf.Type)
	default:
		return nil, fmt.Errorf("unknown type cache config: %s", cconf.Type)
	}
}

func makeCacheConfigValid(c *config.CacheConfig) {
	if c.Type == "" {
		c.Type = CACHE_TYPE_MEM
	}
	if c.Max <= 0 {
		c.Max = CACHE_MAX
	}
	if c.DefaulExpireMinute <= 0 {
		c.DefaulExpireMinute = CACHE_DEFAULT_EXPIRE
	}
}
