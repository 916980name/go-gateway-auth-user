package cache

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"api-gateway/pkg/util"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client        *redis.Client
	name          string
	max           int
	defaultExpire time.Duration
	count         atomic.Int32
}

func NewRedisCache(name string, maxSize int, defaultExpire time.Duration, client *redis.Client) (CacheOper, error) {
	if name == "" {
		name, _ = util.GenerateRandomString(6)
	}
	if maxSize <= 0 {
		maxSize = DEFAULT_MAX_SIZE
	}
	if defaultExpire <= 0 {
		defaultExpire = DEFAULT_EXPIRE_TIME
	}
	return &RedisCache{
		client:        client,
		name:          name,
		max:           maxSize,
		defaultExpire: defaultExpire,
		count:         atomic.Int32{},
	}, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value interface{}) error {
	return c.SetExpire(ctx, key, value, c.defaultExpire)
}

func (c *RedisCache) SetExpire(ctx context.Context, key string, value interface{}, expire time.Duration) error {
	if checkFull(c) {
		return fmt.Errorf("cache full: %d", c.count.Load())
	}
	key = prefixRedisKey(c.name, key)
	err := c.client.Set(ctx, key, value, expire).Err()
	if err != nil {
		return fmt.Errorf("%s cache set fail: %s", key, err)

	}
	c.count.Add(1)
	return nil
}

func (c *RedisCache) Get(ctx context.Context, key string) (interface{}, error) {
	key = prefixRedisKey(c.name, key)
	if x, err := c.client.Get(ctx, key).Result(); err == nil {
		return x, nil
	} else {
		return nil, fmt.Errorf("%s cache get fail: %s", key, err)
	}
}

func (c *RedisCache) Remove(ctx context.Context, key string) (interface{}, error) {
	key = prefixRedisKey(c.name, key)
	v, err := c.client.Del(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("%s cache remove fail: %s", key, err)
	}
	c.count.Add(-1)
	return v, err
}

func (c *RedisCache) Size() int {
	return int(c.count.Load())
}

func (c *RedisCache) Max() int {
	return c.max
}

func (c *RedisCache) Name() string {
	return c.name
}
