package cache

import "time"

type CacheOper interface {
	Get(key string) (interface{}, error)
	Set(key string, value interface{}) error
	SetExpire(key string, value interface{}, expire time.Duration) error
	Remove(key string) (interface{}, error)
}
