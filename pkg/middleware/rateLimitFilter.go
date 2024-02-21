package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
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

func RateLimitFilter(pf GatewayHandlerFactory, l *RateLimiterRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("rate limit do start")

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
						pass, err := limitByIP(ctx, l.Cache, l.RateLimiterConfig, ip)
						if !pass || err != nil {
							if common.FLAG_DEBUG {
								log.C(ctx).Debugw(fmt.Sprintf("Block IP: %s", ip))
							}
							http.Error(w, "", http.StatusForbidden)
							return
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
							if common.FLAG_DEBUG {
								log.C(ctx).Debugw(fmt.Sprintf("Block USER: %s", user))
							}
							http.Error(w, "", http.StatusForbidden)
							return
						}
					default:
					}
				}
			}

			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("rate limit do end")
		}
	}
}

func limitByIP(ctx context.Context, cache *cache.CacheOper, cfg *config.RateLimiterConfig, ip string) (bool, error) {
	if ip == "" {
		// there is no reason ip could not found
		return false, nil
	}
	key := fmt.Sprintf("%s%s%s", cfg.Name, STR_LIMIT_IP, ip)
	log.C(ctx).Debugw(fmt.Sprintf("IP key: %s", key))
	limiter, err := (*cache).Get(key)
	if err != nil {
		limiter = initIPLimiter(cfg)
	}
	(*cache).SetExpire(key, limiter, 30*time.Minute)
	l, ok := limiter.(*ratelimiter.RateLimiter)
	if !ok {
		return false, nil
	} else {
		return l.Acquire(1), nil
	}
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
	limiter, err := (*cache).Get(key)
	if err != nil {
		limiter = initUserLimiter(cfg)
	}
	(*cache).SetExpire(key, limiter, 30*time.Minute)
	l, ok := limiter.(*ratelimiter.RateLimiter)
	if !ok {
		return false, nil
	} else {
		return l.Acquire(1), nil
	}
}

func initUserLimiter(cfg *config.RateLimiterConfig) *ratelimiter.RateLimiter {
	log.Debugw(fmt.Sprintf("init User Limiter: %s, cache: %s, max: %d", cfg.Name, cfg.CacheName, cfg.Max))
	r := ratelimiter.NewRateLimiter(cfg.Max, cfg.RefillInterval, cfg.RefillNumber)
	return r
}
