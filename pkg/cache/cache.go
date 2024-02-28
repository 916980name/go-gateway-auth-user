package cache

import (
	"context"
	"fmt"
	"time"
)

type CacheOper interface {
	Get(ctx context.Context, key string) (interface{}, error)
	Set(ctx context.Context, key string, value interface{}) error
	SetExpire(ctx context.Context, key string, value interface{}, expire time.Duration) error
	Remove(ctx context.Context, key string) (interface{}, error)
	Size() int
	Max() int
	Name() string
}

const (
	DEFAULT_EXPIRE_TIME = 5 * time.Minute
	DEFAULT_MAX_SIZE    = 100000
)

func checkFull(c CacheOper) bool {
	return c.Size()+1 >= c.Max()
}

func prefixRedisKey(cacheName string, key string) string {
	return fmt.Sprintf("%s-%s", cacheName, key)
}
