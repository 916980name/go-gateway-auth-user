package gateway

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/middleware"
	"api-gateway/pkg/proxy"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/gorilla/mux"
)

func initRoutes(sites []*config.Site, r *mux.Router) error {
	var counter atomic.Int32
	rateLimiterFilters := make(map[string]*middleware.RateLimiterRequirements)

	for _, site := range sites {
		subR := r.Host(site.HostName).Subrouter()

		initRateLimiterFilters(site.RateLimiter, rateLimiterFilters)
		inoutFilterConfig := site.InOutFilter
		if (inoutFilterConfig != nil && inoutFilterConfig.RefreshTokenPath != "") && site.OnlineCache != "" {
			log.Warnw("feature [RefreshToken] may not use with feature [OnlineCache], that does not make sense")
		}
		if site.JWTConfig != nil {
			initRSA(site.JWTConfig)
		}
		var onlineCache *cache.CacheOper
		if site.OnlineCache != "" {
			onlineCache = initSiteOnlineCache(site.OnlineCache)
		}

		for _, item := range site.Routes {
			counter.Add(1)
			newR := subR.Name(fmt.Sprint(counter.Load()))
			if strings.Contains(item.Path, "**") {
				// Remove "**" from the string
				result := strings.Replace(item.Path, "**", "", -1)
				newR.PathPrefix(result)
			} else {
				newR.Path(item.Path)
			}

			if item.Method != "" {
				methods := strings.Split(item.Method, ",")
				common.StringArrayOpt(methods, func(s string) string { return strings.TrimSpace(s) })
				newR.Methods(methods...)
			}

			backend := strings.Replace(item.Route, "http://", "", -1)

			// begin build route
			chain := handleMuxChain(backend)(nil)

			// add login/logout middleware
			if inoutFilterConfig != nil {
				for _, v := range inoutFilterConfig.LoginPath {
					if item.Path == v {
						if loginF, err := buildLoginFilter(inoutFilterConfig, onlineCache, v); err != nil {
							log.Errorw("", "error", err)
						} else {
							chain = loginF(chain)
						}
						break
					}
				}
				if item.Path == inoutFilterConfig.LogoutPath {
					if logoutF, err := buildLogoutFilter(inoutFilterConfig, onlineCache); err != nil {
						log.Errorw("", "error", err)
					} else {
						chain = logoutF(chain)
					}
				} else if item.Path == inoutFilterConfig.RefreshTokenPath {
					chain = middleware.NewRefreshTokenHandler(onlineCache, rsaPublicKey, rsaPrivateKey, inoutFilterConfig.CookieEnabled)(nil)
				}
			}
			// add login/logout middleware finish

			// add rate limit middleware
			var rateLimiterRequirement *middleware.RateLimiterRequirements
			var ok bool
			if item.RateLimiter != nil {
				// route limiter first
				initRateLimiterFilters(item.RateLimiter, rateLimiterFilters)
				rateLimiterRequirement, ok = rateLimiterFilters[item.RateLimiter.LimiterName]
				if !ok {
					log.Warnw(fmt.Sprintf("RateLimiterRequirements item.RateLimiter [%s] not found", item.RateLimiter.LimiterName))
				}
			} else if site.RateLimiter != nil {
				rateLimiterRequirement, ok = rateLimiterFilters[site.RateLimiter.LimiterName]
				if !ok {
					log.Warnw(fmt.Sprintf("RateLimiterRequirements site.RateLimiter [%s] not found", site.RateLimiter.LimiterName))
				}
			}
			var needAuth, needFUser, needFIp, haveAuth bool
			if item.Privilege != "" {
				needAuth = true
			}
			if rateLimiterRequirement != nil && strings.Contains(rateLimiterRequirement.LimitTypes, middleware.STR_LIMIT_USER) {
				needFUser = true
			}
			if rateLimiterRequirement != nil && strings.Contains(rateLimiterRequirement.LimitTypes, middleware.STR_LIMIT_IP) {
				needFIp = true
			}
			if needFUser {
				chain = buildChainRateLimiterFilter(chain, rateLimiterRequirement, middleware.STR_LIMIT_USER)
				if needAuth && !haveAuth {
					chain = buildChainAuthFilter(chain, item.Privilege, onlineCache)
					haveAuth = true
				}
			}
			if needAuth && !haveAuth {
				chain = buildChainAuthFilter(chain, item.Privilege, onlineCache)
				haveAuth = true
			}
			if needFIp {
				chain = buildChainRateLimiterFilter(chain, rateLimiterRequirement, middleware.STR_LIMIT_IP)
			}
			// add rate limit middleware finish

			// add request id, ip info retrieve middleware
			chain = middleware.RequestFilter()(chain)
			newR.HandlerFunc(handleMuxChainFunc(chain))
		}

		// site 404
		subR.PathPrefix("/").HandlerFunc(handleMuxChainFunc(middleware.RequestFilter()(handler404)))
	}
	// global 404
	r.PathPrefix("/").HandlerFunc(handleMuxChainFunc(middleware.RequestFilter()(handler404)))
	log.Debugw(fmt.Sprintf("Route init count: %d", counter.Load()))
	if common.FLAG_DEBUG {
		err := r.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
			pathTemplate, err := route.GetPathTemplate()
			if err == nil {
				fmt.Println("ROUTE:", pathTemplate)
			}
			host, err := route.GetHostTemplate()
			if err == nil {
				fmt.Println("HOST:", host)
			}
			pathRegexp, err := route.GetPathRegexp()
			if err == nil {
				fmt.Println("Path regexp:", pathRegexp)
			}
			queriesTemplates, err := route.GetQueriesTemplates()
			if err == nil {
				fmt.Println("Queries templates:", strings.Join(queriesTemplates, ","))
			}
			queriesRegexps, err := route.GetQueriesRegexp()
			if err == nil {
				fmt.Println("Queries regexps:", strings.Join(queriesRegexps, ","))
			}
			methods, err := route.GetMethods()
			if err == nil {
				fmt.Println("Methods:", strings.Join(methods, ","))
			}
			fmt.Println()
			return nil
		})
		if err != nil {
			fmt.Println(err)
		}
	}
	return nil
}

func handler404(ctx context.Context, request *http.Request) (*http.Response, error) {
	if request.URL.Path != "/" {
		log.C(ctx).Infow("not found", "path", request.RequestURI)
		t := &http.Response{
			StatusCode: http.StatusNotFound,
			Body:       io.NopCloser(bytes.NewBufferString("not found")),
		}
		return t, nil
	}
	return nil, fmt.Errorf("Undefined")
}

func buildLoginFilter(cfg *config.LoginLogoutFilterConfig, onlineCache *cache.CacheOper, whichPath string) (proxy.Middleware, error) {
	loginLimiter, ok := RateLimiterConfigs[cfg.LimiterName]
	if !ok {
		return nil, fmt.Errorf("limiter name %s not found", cfg.LimiterName)
	}
	blackListCache, ok := Caches[loginLimiter.CacheName]
	if !ok {
		return nil, fmt.Errorf("black list cache %s not found", loginLimiter.CacheName)
	}
	r := &middleware.LoginFilterRequirements{
		BlacklistCache:             blackListCache,
		BlacklistRateLimiterConfig: loginLimiter,
		OnlineCache:                onlineCache,
		LoginPath:                  whichPath,
		PriKey:                     rsaPrivateKey,
		RefreshTokenPath:           cfg.RefreshTokenPath,
		CookieEnabled:              cfg.CookieEnabled,
	}
	return middleware.LoginFilter(r), nil
}

func buildLogoutFilter(cfg *config.LoginLogoutFilterConfig, onlineCache *cache.CacheOper) (proxy.Middleware, error) {
	r := &middleware.LogoutFilterRequirements{
		OnlineCache:   onlineCache,
		LogoutPath:    cfg.LogoutPath,
		CookieEnabled: cfg.CookieEnabled,
	}
	return middleware.LogoutFilter(r), nil
}

func buildChainRateLimiterFilter(chain proxy.Proxy, r *middleware.RateLimiterRequirements, t string) proxy.Proxy {
	m := middleware.RateLimitFilter(
		&middleware.RateLimiterRequirements{
			Cache:             r.Cache,
			RateLimiterConfig: r.RateLimiterConfig,
			LimitTypes:        t,
		})
	return m(chain)
}

func buildChainAuthFilter(chain proxy.Proxy, privileges string, onlineCache *cache.CacheOper) proxy.Proxy {
	m := middleware.AuthFilter(middleware.AuthRequirements{
		Privileges:  privileges,
		PubKey:      rsaPublicKey,
		PriKey:      rsaPrivateKey,
		OnlineCache: onlineCache,
	})
	return m(chain)
}

func initSiteOnlineCache(cacheName string) *cache.CacheOper {
	onlineCache, ok := Caches[cacheName]
	if !ok {
		log.Errorw(fmt.Sprintf("online cache: %s not found", cacheName))
		return nil
	}
	return onlineCache
}

func initRateLimiterFilters(rc *config.RateLimiterFilterConfig, rateLimiterFilters map[string]*middleware.RateLimiterRequirements) {
	if rc == nil {
		return
	}
	if rc.LimiterName == "" {
		log.Warnw("undefine limiter name")
		return
	}
	_, ok := rateLimiterFilters[rc.LimiterName]
	if ok {
		// this had inited, return
		return
	}
	limiter, ok := RateLimiterConfigs[rc.LimiterName]
	if !ok {
		log.Warnw(fmt.Sprintf("limiter name %s not found", rc.LimiterName))
		return
	}
	cache, ok := Caches[limiter.CacheName]
	if !ok {
		log.Warnw(fmt.Sprintf("cache name %s not found", limiter.CacheName))
		return
	}
	f := &middleware.RateLimiterRequirements{
		Cache:             cache,
		RateLimiterConfig: limiter,
		LimitTypes:        rc.LimitType,
	}
	rateLimiterFilters[rc.LimiterName] = f
}

func handleMuxChainFunc(p proxy.Proxy) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		crw := proxy.NewCustomResponseWriter(w)
		ctx := context.Background()
		proxy.HandleProxyResponse(ctx, crw, r, p)
	}
}

func handleMuxChain(backend string) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
			resp, err := proxy.NewHTTPProxyDetailed(backend)(ctx, r)
			if err != nil {
				log.Errorw(err.Error())
				return nil, common.NewHTTPError("", http.StatusInternalServerError)
			}
			// https://lets-go.alexedwards.net/sample/02.04-customizing-http-headers.html
			// Important: Changing the response header map after a call to w.WriteHeader() or w.Write()
			//   will have no effect on the headers that the user receives. You need to make sure that
			//    your response header map contains all the headers you want before you call these methods.
			return resp, err
		}
	}
}
