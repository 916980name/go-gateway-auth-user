package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/db/dbredis"
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
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
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
						key := fmt.Sprintf("%s%s%s", l.RateLimiterConfig.Name, STR_LIMIT_IP, ip)
						pass, err := limitByIP(ctx, l.Cache, l.RateLimiterConfig, key, ip)
						if !pass || err != nil {
							log.C(ctx).Warnw(fmt.Sprintf("Block IP: %s", ip))
							return nil, common.NewHTTPError("", http.StatusTooManyRequests)
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
						pass, err := limitByUser(ctx, l.Cache, l.RateLimiterConfig, user)
						if !pass || err != nil {
							log.C(ctx).Warnw(fmt.Sprintf("Block USER: %s", user))
							return nil, common.NewHTTPError("", http.StatusTooManyRequests)
						}
					default:
					}
				}
			}

			resp, err := next(ctx, r)
			log.C(ctx).Debugw(fmt.Sprintf("<-- RateLimitFilter do end <-- %s", l.LimitTypes))
			return resp, err
		}
	}
}

func limitByIP(ctx context.Context, cache *cache.CacheOper, cfg *config.RateLimiterConfig, key string, ip string) (bool, error) {
	if ip == "" {
		// there is no reason ip could not found
		return false, nil
	}
	log.C(ctx).Debugw(fmt.Sprintf("IP key: %s", key))
	limiter, err := (*cache).Get(ctx, key)
	if err != nil { // "not found in cache"
		if dbredis.IsErrNotFound(err) {
			limiter = initIPLimiter(cfg)
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
	setErr := (*cache).SetExpire(ctx, key, l, time.Duration(expire)*time.Minute)
	if setErr != nil {
		return false, setErr
	}
	return pass, nil
}

func initIPLimiter(cfg *config.RateLimiterConfig) *ratelimiter.RateLimiter {
	log.Debugw(fmt.Sprintf("init IP Limiter: %s, cache: %s, max: %d", cfg.Name, cfg.CacheName, cfg.Max))
	r := ratelimiter.NewRateLimiter(cfg.Max, cfg.RefillInterval, cfg.RefillNumber)
	return r
}

func limitByUser(ctx context.Context, cache *cache.CacheOper, cfg *config.RateLimiterConfig, user string) (bool, error) {
	// there could be no privilege strict in some interface, the 'user' could not exist
	if user == "" {
		return true, nil
	}
	key := fmt.Sprintf("%s%s%s", cfg.Name, STR_LIMIT_USER, user)
	limiter, err := (*cache).Get(ctx, key)
	if err != nil {
		if dbredis.IsErrNotFound(err) {
			limiter = initUserLimiter(cfg)
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
	setErr := (*cache).SetExpire(ctx, key, l, time.Duration(expire)*time.Minute)
	if setErr != nil {
		return false, setErr
	}
	return pass, nil
}

func initUserLimiter(cfg *config.RateLimiterConfig) *ratelimiter.RateLimiter {
	log.Debugw(fmt.Sprintf("init User Limiter: %s, cache: %s, max: %d", cfg.Name, cfg.CacheName, cfg.Max))
	r := ratelimiter.NewRateLimiter(cfg.Max, cfg.RefillInterval, cfg.RefillNumber)
	return r
}
