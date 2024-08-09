package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/ratelimiter"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	LIMIT_IP = iota
	LIMIT_USER

	STR_LIMIT_IP   = "limiterIP"
	STR_LIMIT_USER = "limiterUSER"

	DEFAULT_LIMITER_CACHE_MINUTE = 30
)

var (
	TypeMap = map[string]int{}
)

func init() {
	TypeMap[STR_LIMIT_IP] = LIMIT_IP
	TypeMap[STR_LIMIT_USER] = LIMIT_USER
}

type RateLimiterRequirements struct {
	Cache             *cache.CacheOper
	RateLimiterConfig *config.RateLimiterConfig
	LimitTypes        string
}

func RateLimitFilter(l *RateLimiterRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			log.C(ctx).Debugw(fmt.Sprintf("--> RateLimitFilter do start --> %s", l.LimitTypes))

			for _, item := range strings.Split(l.LimitTypes, ",") {
				if lType, ok := TypeMap[strings.TrimSpace(item)]; ok {
					switch lType {
					case LIMIT_IP:
						v := ctx.Value(common.Trace_request_ip{})
						ip, ok := v.(string) // incase if nil
						if !ok {
							if common.FLAG_DEBUG {
								log.C(ctx).Debugw("IP not got")
							}
							continue
						}
						key := fmt.Sprintf("%s:%s:%s", l.RateLimiterConfig.Name, STR_LIMIT_IP, ip)
						pass, err := limitByKey(ctx, l.Cache, l.RateLimiterConfig, key)
						if !pass || err != nil {
							log.C(ctx).Warnw(fmt.Sprintf("Block IP: %s", ip), "error", err)
							return ctx, nil, common.NewHTTPError("", http.StatusTooManyRequests)
						}
					case LIMIT_USER:
						v := ctx.Value(common.Trace_request_user{})
						user, ok := v.(string) // incase if nil
						if !ok {
							if common.FLAG_DEBUG {
								log.C(ctx).Debugw("User not got")
							}
							continue
						}
						key := fmt.Sprintf("%s:%s:%s", l.RateLimiterConfig.Name, STR_LIMIT_USER, user)
						pass, err := limitByKey(ctx, l.Cache, l.RateLimiterConfig, key)
						if !pass || err != nil {
							log.C(ctx).Warnw(fmt.Sprintf("Block USER: %s", user), "error", err)
							return ctx, nil, common.NewHTTPError("", http.StatusTooManyRequests)
						}
					default:
					}
				}
			}

			ctx, resp, err := next(ctx, r)
			log.C(ctx).Debugw(fmt.Sprintf("<-- RateLimitFilter do end <-- %s", l.LimitTypes))
			return ctx, resp, err
		}
	}
}

func limitByKey(ctx context.Context, c *cache.CacheOper, cfg *config.RateLimiterConfig, key string) (bool, error) {
	log.C(ctx).Debugw(fmt.Sprintf("limit key: %s", key))
	switch ct := (*c).Type(); ct {
	case cache.TYPE_MEM:
		limiter, err := (*c).Get(ctx, key)
		if err != nil { // "not found in cache"
			if strings.Contains(err.Error(), "not found in cache") {
				limiter = initLimiter(cfg)
			} else {
				return false, err
			}
		}
		l, err := ratelimiter.UnmarshalRateLimiterInterface(limiter)
		if err != nil {
			return false, err
		}
		pass := l.Acquire(1)
		expire := max(DEFAULT_LIMITER_CACHE_MINUTE, cfg.RefillInterval)
		setErr := (*c).SetExpire(ctx, key, l, time.Duration(expire)*time.Minute)
		if setErr != nil {
			return false, setErr
		}
		return pass, nil
	case cache.TYPE_REDIS:
		rd := (*c).(*cache.RedisCache)
		pass, err := rd.RateLimit(ctx, key, cfg.RefillInterval, cfg.RefillNumber, cfg.Max, 1, DEFAULT_LIMITER_CACHE_MINUTE)
		if err != nil { // "not found in cache"
			return false, err
		}
		return pass, nil
	default:
		return false, fmt.Errorf("unknown cache type: %v", ct)
	}
}

func initLimiter(cfg *config.RateLimiterConfig) *ratelimiter.RateLimiter {
	log.Debugw(fmt.Sprintf("init Limiter: %s, cache: %s, max: %d", cfg.Name, cfg.CacheName, cfg.Max))
	r := ratelimiter.NewRateLimiter(cfg.Max, cfg.RefillInterval, cfg.RefillNumber)
	return r
}
