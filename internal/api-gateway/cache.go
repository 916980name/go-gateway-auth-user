package gateway

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/config"
	"api-gateway/pkg/db/dbredis"
	"api-gateway/pkg/log"
	"context"
	"fmt"
	"time"
)

const (
	CACHE_TYPE_MEM   = "mem"
	CACHE_TYPE_REDIS = "redis"
	CACHE_MAX        = 10000
)

var (
	Caches              map[string]*cache.CacheOper = make(map[string]*cache.CacheOper)
	CurrentRedisOptions *dbredis.RedisOptions
)

func InitCaches(ctx context.Context, cs []*config.CacheConfig) error {
	for _, item := range cs {
		if item.Name == "" {
			log.Warnw("un-named cache config")
			continue
		}
		makeCacheConfigValid(item)
		c, e := initByType(ctx, item)
		if e != nil {
			log.Errorw(e.Error())
			continue
		}
		if Caches[item.Name] != nil {
			log.Warnw(fmt.Sprintf("init cache: %s, have been substitude !!!", item.Name))
		}
		Caches[item.Name] = c
	}

	return nil
}

func initByType(ctx context.Context, cconf *config.CacheConfig) (*cache.CacheOper, error) {
	switch cconf.Type {
	case CACHE_TYPE_MEM:
		log.Infow(fmt.Sprintf("init mem cache: %s", cconf.Name))
		c, e := cache.NewMemCache(cconf.Name, cconf.Max, time.Duration(cconf.DefaulExpireMinute)*time.Minute)
		return &c, e
	case CACHE_TYPE_REDIS:
		log.Infow(fmt.Sprintf("init redis cache: %s", cconf.Name))
		c, e := cache.NewRedisCache(cconf.Name, cconf.Max,
			time.Duration(cconf.DefaulExpireMinute*int(time.Minute)), dbredis.GetClient(ctx, CurrentRedisOptions.ConnectionString))
		return &c, e
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
		c.DefaulExpireMinute = int(cache.DEFAULT_EXPIRE_TIME.Minutes())
	}
}

func InitRedis(ctx context.Context, cfg *dbredis.RedisOptions) {
	CurrentRedisOptions = dbredis.ReadRedisOptions(cfg.ConnectionString)
	c := dbredis.GetClient(ctx, CurrentRedisOptions.ConnectionString)
	if c == nil {
		log.Errorw("redis connect fail")
	}
}
