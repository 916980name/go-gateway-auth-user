package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/ratelimiter"
	"bufio"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"time"
)

const (
	STR_LOGIN_OUT_FILTER      = "loginout"
	JWT_TOKEN_DEFAULT_TIMEOUT = 24 * time.Hour
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
			if resp.StatusCode >= 300 || resp.StatusCode < 200 {
				if common.FLAG_DEBUG {
					log.C(ctx).Debugw(fmt.Sprintf("LoginFilter attention: %s", ip))
				}
				attentionIP(ctx, l, ip)
			} else {
				// login success
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
				m := make(map[string]interface{})
				err = json.Unmarshal(bodyBytes, &m)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter read userinfo failed", "error", err)
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				token, err := jwt.GenerateJWTRSA(m, JWT_TOKEN_DEFAULT_TIMEOUT, l.PriKey)
				if err != nil {
					log.C(ctx).Errorw("LoginFilter gen token failed", "error", err)
					return nil, NewHTTPError("", http.StatusInternalServerError)
				}
				resp.Header.Add("Authorization", fmt.Sprintf("%s %s", "Bearer", token))
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

func attentionIP(ctx context.Context, l *LoginFilterRequirements, ip string) (bool, error) {
	key := fmt.Sprintf("%s%s%s", l.BlacklistRateLimiterConfig.Name, STR_LOGIN_OUT_FILTER, ip)
	pass, err := limitByIP(ctx, l.BlacklistCache, l.BlacklistRateLimiterConfig, key, ip)
	log.C(ctx).Debugw(fmt.Sprintf("login pass? %v", pass))
	return pass, err
}
