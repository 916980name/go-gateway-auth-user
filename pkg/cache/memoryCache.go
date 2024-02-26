package cache

import (
	"fmt"
	"time"

	"api-gateway/pkg/log"

	"github.com/bluele/gcache"
)

const (
	DEFAULT_EXPIRE_TIME = 5 * time.Minute
	DEFAULT_MAX_SIZE    = 100000
)

type MemCache struct {
	c   gcache.Cache
	max int
}

func NewMemCache(maxSize int, defaultExpire time.Duration) (CacheOper, error) {
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
	return &MemCache{c: c, max: maxSize}, nil
}

func (c *MemCache) Set(key string, value interface{}) error {
	if checkFull(c) {
		return fmt.Errorf("cache full: %d", c.c.Len(false))
	}
	c.c.Set(key, value)
	return nil
}

func checkFull(c *MemCache) bool {
	return c.c.Len(false)+1 >= c.max
}

/*
// Want performance? Store pointers!
c.Set("foo", &MyStruct, cache.DefaultExpiration)

	if x, found := c.Get("foo"); found {
		foo := x.(*MyStruct)
			// ...
	}
*/

func (c *MemCache) SetExpire(key string, value interface{}, expire time.Duration) error {
	if checkFull(c) {
		return fmt.Errorf("cache full: %d", c.c.Len(false))
	}
	c.c.SetWithExpire(key, value, expire)
	return nil
}

func (c *MemCache) Get(key string) (interface{}, error) {
	if x, err := c.c.Get(key); err == nil {
		return x, nil
	} else {
		return nil, fmt.Errorf("%s not found in cache", key)
	}
}

func (c *MemCache) Remove(key string) (interface{}, error) {
	v, err := c.Get(key)
	c.c.Remove(key)
	return v, err
}
