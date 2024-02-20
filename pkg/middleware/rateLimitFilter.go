package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/log"
	"api-gateway/pkg/ratelimiter"
	"context"
	"fmt"
	"net/http"
	"time"
)

const (
	LIMIT_IP = iota
	LIMIT_USER

	STR_LIMIT_IP   = "limiterIP"
	STR_LIMIT_USER = "limiterUSER"
)

var (
	TypeMap = map[string]int{}
)

func init() {
	TypeMap[STR_LIMIT_IP] = LIMIT_IP
	TypeMap[STR_LIMIT_USER] = LIMIT_USER
}

type RateLimiterRequirements struct {
	cache      cache.CacheOper
	limitTypes string
}

func RateLimitFilter(pf GatewayHandlerFactory, l *RateLimiterRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("rate limit do start")

			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("rate limit do end")
		}
	}
}

func limitByIP(ctx context.Context, cache cache.CacheOper, ip string) (bool, error) {
	key := fmt.Sprintf("%s%s", STR_LIMIT_IP, ip)
	limiter, err := cache.Get(key)
	if err != nil {
		limiter = initIPLimiter()
		cache.SetExpire(key, &limiter, 30*time.Minute)
	}
	return limiter.(*ratelimiter.RateLimiter).Acquire(1), nil
}

func initIPLimiter() *ratelimiter.RateLimiter {

	return nil
}
