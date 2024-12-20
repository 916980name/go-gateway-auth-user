package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/ratelimiter"
	"api-gateway/pkg/util"
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	STR_LOGIN_OUT_FILTER = "loginout"
)

type LoginFilterRequirements struct {
	BlacklistCache             *cache.CacheOper
	BlacklistRateLimiterConfig *config.RateLimiterConfig
	OnlineCache                *cache.CacheOper
	LoginPath                  string
	PriKey                     *rsa.PrivateKey
	RefreshTokenPath           string
	CookieEnabled              bool
}

type LogoutFilterRequirements struct {
	OnlineCache   *cache.CacheOper
	LogoutPath    string
	CookieEnabled bool
}

func LoginFilter(l *LoginFilterRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			log.C(ctx).Debugw("--> LoginFilter do start -->")
			// do before login
			// check blacklist, IP/User
			ip := getClientIP(r)
			pass, err := checkCouldPass(ctx, ip, l)
			if err != nil {
				log.C(ctx).Errorw("LoginFilter error", "error", err)
				return ctx, nil, common.NewHTTPError("", http.StatusForbidden)
			}
			if !pass {
				log.C(ctx).Infow(fmt.Sprintf("LoginFilter BLOCK: %s", ip))
				return ctx, nil, common.NewHTTPError("", http.StatusForbidden)
			}

			ctx, resp, err := next(ctx, r)
			if err != nil {
				log.C(ctx).Errorw("LoginFilter error", "error", err)
				return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
			}
			if r.Method == "OPTIONS" {
				log.C(ctx).Debugw("<-- LoginFilter do end <--")
				return ctx, resp, err
			}
			// do after login
			/*  login fail
				in x time duration, add to black list
			login suc
				remove from blacklist
				generate JWT token
				save token to cache
			*/
			if resp.StatusCode >= 300 || resp.StatusCode < 200 {
				// login fail
				if common.FLAG_DEBUG {
					log.C(ctx).Debugw(fmt.Sprintf("LoginFilter attention: %s", ip))
				}
				attentionIP(ctx, l, ip)
			} else {
				// login success
				// remove from blacklist
				removeBlacklistByIP(ctx, l.BlacklistCache, l.BlacklistRateLimiterConfig, ip)
				// generate JWT token
				dataCopy, err := httputil.DumpResponse(resp, true)
				if err != nil {
					return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
				}
				reader := bufio.NewReader(bytes.NewBuffer(dataCopy))
				// Parse the response using http.ReadResponse
				copyResp, err := http.ReadResponse(reader, nil)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter read response failed", "error", err)
					return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
				}
				bodyBytes, err := io.ReadAll(copyResp.Body)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter read resp body failed", "error", err)
					return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
				}
				err = genAndSetTokens(ctx, bodyBytes, l, resp)
				if err != nil {
					return ctx, nil, err
				}
			}

			log.C(ctx).Debugw("<-- LoginFilter do end <--")
			return ctx, resp, err
		}
	}
}

func removeBlacklistByIP(ctx context.Context, c *cache.CacheOper, cfg *config.RateLimiterConfig, ip string) {
	if cfg == nil {
		return
	}
	cacheKey := getIPBlacklistCacheKey(cfg, ip)
	log.C(ctx).Debugw(fmt.Sprintf("remove blacklist limit key: %s", cacheKey))
	switch ct := (*c).Type(); ct {
	case cache.TYPE_MEM:
		_, err := (*c).Remove(ctx, cacheKey)
		if err != nil {
			log.C(ctx).Warnw(err.Error())
		}
	case cache.TYPE_REDIS:
		rd := (*c).(*cache.RedisCache)
		err := rd.RateLimitRemove(ctx, cacheKey)
		if err != nil {
			log.C(ctx).Warnw(err.Error())
		}
	default:
		log.C(ctx).Warnw("unknown type")
	}
}

func genAndSetTokens(ctx context.Context, bodyBytes []byte, l *LoginFilterRequirements, resp *http.Response) error {
	var token, refreshToken string
	var err error
	if l.RefreshTokenPath != "" {
		token, refreshToken, err = generateTwoTokens(ctx, bodyBytes, l.OnlineCache, l.PriKey)
	} else {
		token, err = generateAccessToken(ctx, bodyBytes, l.OnlineCache, l.PriKey)
	}
	if err != nil {
		log.C(ctx).Errorw("LoginFilter generateTwoTokens failed", "error", err)
		return common.NewHTTPError("", http.StatusInternalServerError)
	}
	resp.Header.Set(HEADER_ACCESS_TOKEN, token)
	if l.RefreshTokenPath != "" {
		resp.Header.Set(HEADER_REFRESH_TOKEN, refreshToken)
	}
	if l.CookieEnabled {
		tokenTO := time.Now().Add(JWT_TOKEN_DEFAULT_TIMEOUT)
		util.ResponseSetRootCookie(resp, HEADER_ACCESS_TOKEN, token, &tokenTO)
	}
	return nil
}

func LogoutFilter(l *LogoutFilterRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			log.C(ctx).Debugw("LogoutFilter do start")
			// do before logout
			// remove token from cache
			if l.OnlineCache != nil {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				key := getOnlineCacheKey(ctx.Value(common.Trace_request_user{}).(string))
				cacheMd5, err := (*l.OnlineCache).Get(ctx, key)
				if err == nil && cacheMd5 == common.StringToMD5Base64(token) {
					(*l.OnlineCache).Remove(ctx, key)
				}
			}

			ctx, resp, err := next(ctx, r)
			// do after logout
			if l.CookieEnabled {
				tokenTO := time.Unix(0, 0)
				refreshTokenTO := time.Unix(0, 0)
				util.ResponseSetRootCookie(resp, HEADER_ACCESS_TOKEN, "", &tokenTO)
				util.ResponseSetRootCookie(resp, HEADER_REFRESH_TOKEN, "", &refreshTokenTO)
			}

			log.C(ctx).Debugw("LogoutFilter do end")
			return ctx, resp, err
		}
	}
}

func checkCouldPass(ctx context.Context, ip string, lfr *LoginFilterRequirements) (bool, error) {
	if lfr.BlacklistRateLimiterConfig == nil {
		return true, nil
	}
	key := getIPBlacklistCacheKey(lfr.BlacklistRateLimiterConfig, ip)
	switch ct := (*lfr.BlacklistCache).Type(); ct {
	case cache.TYPE_MEM:
		limiter, err := (*lfr.BlacklistCache).Get(ctx, key)
		// not in blacklist, pass
		if err != nil {
			return true, nil
		}
		l, err := ratelimiter.UnmarshalRateLimiterInterface(limiter)
		if err != nil {
			return false, err
		}
		// if acquire suc, could pass
		return l.Acquire(1), nil
	case cache.TYPE_REDIS:
		rd := (*lfr.BlacklistCache).(*cache.RedisCache)
		pass, err := rd.RateLimitCheck(ctx, key, lfr.BlacklistRateLimiterConfig.RefillInterval,
			lfr.BlacklistRateLimiterConfig.RefillNumber, lfr.BlacklistRateLimiterConfig.Max, 1)
		if err != nil {
			log.C(ctx).Warnw(err.Error())
		}
		return pass, err
	default:
		return false, fmt.Errorf("unknown type")
	}
}

func getIPBlacklistCacheKey(cfg *config.RateLimiterConfig, ip string) string {
	return fmt.Sprintf("%s:%s:%s:%s", cfg.CacheName, cfg.Name, STR_LOGIN_OUT_FILTER, ip)
}

func getOnlineCacheKey(username string) string {
	return fmt.Sprintf("online:%s", username)
}

func attentionIP(ctx context.Context, l *LoginFilterRequirements, ip string) (bool, error) {
	if l.BlacklistRateLimiterConfig == nil {
		return true, nil
	}
	cacheKey := getIPBlacklistCacheKey(l.BlacklistRateLimiterConfig, ip)
	pass, err := limitByKey(ctx, l.BlacklistCache, l.BlacklistRateLimiterConfig, cacheKey)
	log.C(ctx).Debugw(fmt.Sprintf("could call login? %v", pass))
	if err != nil {
		log.C(ctx).Warnw("attentionIP fail", log.TAG_ERR, err)
	}
	return pass, err
}
