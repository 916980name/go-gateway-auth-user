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
)

const (
	STR_LOGIN_OUT_FILTER = "loginout"
)

type LoginFilterRequirements struct {
	BlacklistCache             *cache.CacheOper
	BlacklistRateLimiterConfig *config.RateLimiterConfig
	OnlineCache                *cache.CacheOper
	LoginPath                  string
}

type LogoutFilterRequirements struct {
	OnlineCache *cache.CacheOper
	LogoutPath  string
}

func LoginFilter(pf GatewayHandlerFactory, l *LoginFilterRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w *proxy.CustomResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("--> LoginFilter do start -->")
			// do before login
			// check blacklist, IP/User
			ip := getClientIP(r)
			pass, err := checkCouldPass(ctx, ip, l)
			if err != nil {
				log.C(ctx).Errorw("LoginFilter error", "error", err)
			}
			if !pass {
				log.C(ctx).Infow(fmt.Sprintf("LoginFilter BLOCK: %s", ip))
				http.Error(w, "", http.StatusForbidden)
				return
			}

			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			// do after login
			/*  login fail
				in x time duration, add to black list
			login suc
				remove from blacklist
				generate JWT token
				save token to cache
			*/
			if w.StatusCode >= 300 || w.StatusCode < 200 {
				if common.FLAG_DEBUG {
					log.C(ctx).Debugw(fmt.Sprintf("LoginFilter attention: %s", ip))
				}
				attentionIP(ctx, l, ip)
			}

			log.C(ctx).Debugw("<-- LoginFilter do end <--")
		}
	}
}

func LogoutFilter(pf GatewayHandlerFactory, l *LogoutFilterRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w *proxy.CustomResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("LogoutFilter do start")
			// do before logout
			// remove token from cache

			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			// do after logout

			log.C(ctx).Debugw("LogoutFilter do end")
		}
	}
}

func checkCouldPass(ctx context.Context, ip string, lfr *LoginFilterRequirements) (bool, error) {
	key := fmt.Sprintf("%s%s%s", lfr.BlacklistRateLimiterConfig.Name, STR_LOGIN_OUT_FILTER, ip)
	limiter, err := (*lfr.BlacklistCache).Get(key)
	// not in blacklist, pass
	if err != nil {
		return true, nil
	}
	setErr := (*lfr.BlacklistCache).Set(key, limiter)
	if setErr != nil {
		return false, setErr
	}
	l, ok := limiter.(*ratelimiter.RateLimiter)
	if !ok {
		return false, nil
	} else {
		// if acquire suc, could pass
		return l.Acquire(1), nil
	}
}

func attentionIP(ctx context.Context, l *LoginFilterRequirements, ip string) (bool, error) {
	key := fmt.Sprintf("%s%s%s", l.BlacklistRateLimiterConfig.Name, STR_LOGIN_OUT_FILTER, ip)
	pass, err := limitByIP(ctx, l.BlacklistCache, l.BlacklistRateLimiterConfig, key, ip)
	log.C(ctx).Debugw(fmt.Sprintf("login pass? %v", pass))
	return pass, err
}
