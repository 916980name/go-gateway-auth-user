package cache

import (
	"context"
	"fmt"
	"time"

	"api-gateway/pkg/log"
	"api-gateway/pkg/util"

	"github.com/bluele/gcache"
)

type MemCache struct {
	c    gcache.Cache
	name string
	max  int
}

func NewMemCache(name string, maxSize int, defaultExpire time.Duration) (CacheOper, error) {
	if name == "" {
		name, _ = util.GenerateRandomString(6)
	}
	if maxSize <= 0 {
		maxSize = DEFAULT_MAX_SIZE
	}
	if defaultExpire <= 0 {
		defaultExpire = DEFAULT_EXPIRE_TIME
	}
	c := gcache.New(maxSize).
		Expiration(defaultExpire).
		AddedFunc(func(key, value interface{}) {
			// ...
		}).
		EvictedFunc(func(key, value interface{}) {
			log.Infow(fmt.Sprintf("Evicted key: %s", key))
		}).
		Build()
	return &MemCache{c: c, max: maxSize, name: name}, nil
}

func (c *MemCache) Set(ctx context.Context, key string, value interface{}) error {
	if checkFull(c) {
		return fmt.Errorf("cache full: %d", c.c.Len(false))
	}
	c.c.Set(key, value)
	return nil
}

func (c *MemCache) Size() int {
	return c.c.Len(false)
}

func (c *MemCache) Max() int {
	return c.max
}

func (c *MemCache) Name() string {
	return c.name
}

/*
// Want performance? Store pointers!
c.Set("foo", &MyStruct, cache.DefaultExpiration)

	if x, found := c.Get("foo"); found {
		foo := x.(*MyStruct)
			// ...
	}
*/

func (c *MemCache) SetExpire(ctx context.Context, key string, value interface{}, expire time.Duration) error {
	if checkFull(c) {
		return fmt.Errorf("cache full: %d", c.c.Len(false))
	}
	c.c.SetWithExpire(key, value, expire)
	return nil
}

func (c *MemCache) Get(ctx context.Context, key string) (interface{}, error) {
	if x, err := c.c.Get(key); err == nil {
		return x, nil
	} else {
		return nil, fmt.Errorf("%s not found in cache", key)
	}
}

func (c *MemCache) Remove(ctx context.Context, key string) (interface{}, error) {
	v, err := c.Get(ctx, key)
	c.c.Remove(key)
	return v, err
}
