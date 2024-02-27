package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/ratelimiter"
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
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
}

type LogoutFilterRequirements struct {
	OnlineCache *cache.CacheOper
	LogoutPath  string
}

func LoginFilter(l *LoginFilterRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
			log.C(ctx).Debugw("--> LoginFilter do start -->")
			// do before login
			// check blacklist, IP/User
			ip := getClientIP(r)
			pass, err := checkCouldPass(ctx, ip, l)
			if err != nil {
				log.C(ctx).Errorw("LoginFilter error", "error", err)
				return nil, NewHTTPError("", http.StatusForbidden)
			}
			if !pass {
				log.C(ctx).Infow(fmt.Sprintf("LoginFilter BLOCK: %s", ip))
				return nil, NewHTTPError("", http.StatusForbidden)
			}

			resp, err := next(ctx, r)
			// do after login
			/*  login fail
				in x time duration, add to black list
			login suc
				remove from blacklist
				generate JWT token
				save token to cache
			*/
			cacheKey := getIPBlacklistCacheKey(l.BlacklistRateLimiterConfig.Name, ip)
			if resp.StatusCode >= 300 || resp.StatusCode < 200 {
				// login fail
				if common.FLAG_DEBUG {
					log.C(ctx).Debugw(fmt.Sprintf("LoginFilter attention: %s", ip))
				}
				attentionIP(ctx, l, cacheKey, ip)
			} else {
				// login success
				// remove from blacklist
				(*l.BlacklistCache).Remove(cacheKey)
				// generate JWT token
				dataCopy, err := httputil.DumpResponse(resp, true)
				if err != nil {
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				reader := bufio.NewReader(bytes.NewBuffer(dataCopy))
				// Parse the response using http.ReadResponse
				copyResp, err := http.ReadResponse(reader, nil)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter read response failed", "error", err)
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				bodyBytes, err := io.ReadAll(copyResp.Body)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter read resp body failed", "error", err)
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				token, refreshToken, err := generateTwoTokens(bodyBytes, l.OnlineCache, l.PriKey)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter generateTwoTokens failed", "error", err)
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				// resp.Header.Add("Authorization", fmt.Sprintf("%s %s", "Bearer", token))
				resp.Header.Set(HEADER_ACCESS_TOKEN, token)
				resp.Header.Set(HEADER_REFRESH_TOKEN, refreshToken)
			}

			log.C(ctx).Debugw("<-- LoginFilter do end <--")
			return resp, err
		}
	}
}

func LogoutFilter(l *LogoutFilterRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
			log.C(ctx).Debugw("LogoutFilter do start")
			// do before logout
			// remove token from cache
			if l.OnlineCache != nil {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				key := getOnlineCacheKey(ctx.Value(common.Trace_request_user{}).(string))
				cacheMd5, err := (*l.OnlineCache).Get(key)
				if err == nil && cacheMd5 == common.StringToMD5Base64(token) {
					(*l.OnlineCache).Remove(key)
				}
			}

			resp, err := next(ctx, r)
			// do after logout

			log.C(ctx).Debugw("LogoutFilter do end")
			return resp, err
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

func getIPBlacklistCacheKey(limiterConfigName string, ip string) string {
	return fmt.Sprintf("%s%s%s", limiterConfigName, STR_LOGIN_OUT_FILTER, ip)
}

func getOnlineCacheKey(username string) string {
	return fmt.Sprintf("online-%s", username)
}

func attentionIP(ctx context.Context, l *LoginFilterRequirements, key string, ip string) (bool, error) {
	pass, err := limitByIP(ctx, l.BlacklistCache, l.BlacklistRateLimiterConfig, key, ip)
	log.C(ctx).Debugw(fmt.Sprintf("could call login? %v", pass))
	return pass, err
}
