package cache

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"api-gateway/pkg/util"

	"github.com/redis/go-redis/v9"
)

type RedisCache struct {
	client        *redis.Client
	name          string
	max           int
	defaultExpire time.Duration
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
	}, nil
}

func (c *RedisCache) Set(ctx context.Context, key string, value interface{}) error {
	return c.SetExpire(ctx, key, value, c.defaultExpire)
}

func (c *RedisCache) SetExpire(ctx context.Context, key string, value interface{}, expire time.Duration) error {
	key = prefixRedisKey(c.name, key)
	err := c.client.Set(ctx, key, value, expire).Err()
	if err != nil {
		return fmt.Errorf("%s cache set fail: %s", key, err)

	}
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
	return v, err
}

func (c *RedisCache) Size() int {
	return int(c.client.DBSize(context.Background()).Val())
}

func (c *RedisCache) Max() int {
	return c.max
}

func (c *RedisCache) Name() string {
	return c.name
}

func (c *RedisCache) Type() CacheType {
	return TYPE_REDIS
}

// rate limiter
var rl = redis.NewScript(`
	local refill_time = redis.call('TIME')
	local current_time = tonumber(refill_time[1]) + tonumber(refill_time[2]) / 1000000

	local last_refill_time = tonumber(redis.call('GET', KEYS[2]) or current_time)
	local refill_interval = tonumber(ARGV[1])  -- Pass RefillInterval as ARGV[1]
	local refill_amount = tonumber(ARGV[2])    -- Pass RefillAmount as ARGV[2]
	local max_tokens = tonumber(ARGV[3])       -- Pass MaxTokens as ARGV[3]
	local current_tokens = tonumber(redis.call('GET', KEYS[1]) or max_tokens)
	local aquire_tokens = tonumber(ARGV[4])       -- Pass MaxTokens as ARGV[3]

	local ratio = (current_time - last_refill_time) / refill_interval
	local current_tokens = math.max(0, math.min(max_tokens, current_tokens + ratio * refill_amount - aquire_tokens))

	if current_tokens > 0 then  -- Pass the number of tokens needed as ARGV[4]
		redis.call('SET', KEYS[1], current_tokens, 'EX', ARGV[5])
		redis.call('SET', KEYS[2], current_time, 'EX', ARGV[5])
		return 1
	else
		return 0
	end
	`)

// rate limiter check
var rlc = redis.NewScript(`
	local refill_time = redis.call('TIME')
	local current_time = tonumber(refill_time[1]) + tonumber(refill_time[2]) / 1000000

	local last_refill_time = tonumber(redis.call('GET', KEYS[2]) or current_time)
	local refill_interval = tonumber(ARGV[1])  -- Pass RefillInterval as ARGV[1]
	local refill_amount = tonumber(ARGV[2])    -- Pass RefillAmount as ARGV[2]
	local max_tokens = tonumber(ARGV[3])       -- Pass MaxTokens as ARGV[3]
	local current_tokens = tonumber(redis.call('GET', KEYS[1]) or max_tokens)
	local aquire_tokens = tonumber(ARGV[4])       -- Pass MaxTokens as ARGV[3]

	local ratio = (current_time - last_refill_time) / refill_interval
	local current_tokens = math.max(0, math.min(max_tokens, current_tokens + ratio * refill_amount - aquire_tokens))

	if current_tokens > 0 then  -- Pass the number of tokens needed as ARGV[4]
		return 1
	else
		return 0
	end
	`)

const KEY_SUFFIX_CURRENT_TOKEN = ":ct"
const KEY_SUFFIX_LAST_REFILL = ":lr"

func (c *RedisCache) RateLimit(ctx context.Context, key string,
	refill_interval int, refill_amount int, max_tokens int, aquire_tokens int,
	expire_minute int) (bool, error) {
	expire := math.Max(c.defaultExpire.Minutes(), float64(expire_minute)) * 60
	key = prefixRedisKey(c.name, key)
	keys := []string{key + KEY_SUFFIX_CURRENT_TOKEN, key + KEY_SUFFIX_LAST_REFILL}
	values := []interface{}{refill_interval, refill_amount, max_tokens,
		aquire_tokens, expire}
	result, err := rl.Run(ctx, c.client, keys, values...).Int()
	if err != nil {
		return false, err
	}
	if result == 1 {
		return true, nil
	}
	return false, nil
}

func (c *RedisCache) RateLimitRemove(ctx context.Context, key string) error {
	key = prefixRedisKey(c.name, key)
	keys := []string{key + KEY_SUFFIX_CURRENT_TOKEN, key + KEY_SUFFIX_LAST_REFILL}
	return c.client.Del(ctx, keys...).Err()
}

func (c *RedisCache) RateLimitCheck(ctx context.Context, key string,
	refill_interval int, refill_amount int, max_tokens int, aquire_tokens int) (bool, error) {
	key = prefixRedisKey(c.name, key)
	keys := []string{key + KEY_SUFFIX_CURRENT_TOKEN, key + KEY_SUFFIX_LAST_REFILL}
	values := []interface{}{refill_interval, refill_amount, max_tokens, aquire_tokens}
	result, err := rlc.Run(ctx, c.client, keys, values...).Int()
	if err != nil {
		if strings.Contains(err.Error(), "redis: nil") {
			return true, nil
		}
		return false, err
	}
	if result == 1 {
		return true, nil
	}
	return false, nil
}
