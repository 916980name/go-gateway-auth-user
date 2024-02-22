package gateway

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"api-gateway/pkg/middleware"
	"api-gateway/pkg/proxy"
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

		for _, item := range site.Routes {
			counter.Add(1)
			newR := subR.Name(fmt.Sprint(counter.Load()))
			if strings.Contains(item.Path, "**") {
				// Remove "**" from the string
				result := strings.Replace(item.Path, "**", "", -1)
				// Remove the last character from the string
				result = result[:len(result)-1]
				newR.PathPrefix(result)
			} else {
				newR.Path(item.Path)
			}

			if item.Method != "" {
				newR.Methods(strings.Split(item.Method, ",")...)
			}

			backend := strings.Replace(item.Route, "http://", "", -1)

			// begin build route
			chain := handleMuxChain(backend)

			// add auth middleware

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
				chain = buildChainRequestRateLimiterFilter(chain, rateLimiterRequirement, middleware.STR_LIMIT_USER)
				if needAuth && !haveAuth {
					chain = buildChainAuthFilter(chain, item.Privilege, site.TokenSecret)
					haveAuth = true
				}
			}
			if needAuth && !haveAuth {
				chain = buildChainAuthFilter(chain, item.Privilege, site.TokenSecret)
				haveAuth = true
			}
			if needFIp {
				chain = buildChainRequestRateLimiterFilter(chain, rateLimiterRequirement, middleware.STR_LIMIT_IP)
			}

			// add request id, ip info retrieve middleware
			chain = middleware.RequestFilter(chain)
			newR.HandlerFunc(handleMuxChainFunc(chain))
		}
	}
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

func buildChainRequestRateLimiterFilter(chain middleware.GatewayHandlerFactory, r *middleware.RateLimiterRequirements, t string) middleware.GatewayHandlerFactory {
	chain = middleware.RateLimitFilter(chain,
		&middleware.RateLimiterRequirements{
			Cache:             r.Cache,
			RateLimiterConfig: r.RateLimiterConfig,
			LimitTypes:        t,
		})
	return chain
}

func buildChainAuthFilter(chain middleware.GatewayHandlerFactory, privileges string, tokenSecret string) middleware.GatewayHandlerFactory {
	chain = middleware.AuthFilter(chain, middleware.AuthRequirements{
		Privileges:  privileges,
		TokenSecret: tokenSecret,
	})
	return chain
}

func initRateLimiterFilters(rc *config.RateLimiterFilterConfig, rateLimiterFilters map[string]*middleware.RateLimiterRequirements) {
	if rc.LimiterName == "" {
		log.Warnw("undefine limiter name")
		return
	}
	_, ok := rateLimiterFilters[rc.LimiterName]
	if ok {
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

func handleMuxChain(backend string) middleware.GatewayHandlerFactory {
	return func(next middleware.GatewayContextHandlerFunc) middleware.GatewayContextHandlerFunc {
		return handleMux(backend)
	}
}

func handleMuxChainFunc(pf middleware.GatewayHandlerFactory) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		f := pf(nil)
		f(nil, w, r)
	}
}

func handleMux(backend string) middleware.GatewayContextHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
		resp, err := proxy.NewHTTPProxyDetailed(backend)(ctx, r)
		if err != nil {
			log.Errorw(err.Error())
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.C(ctx).Infow("remote response", "code", resp.StatusCode)

		for k := range w.Header() {
			delete(w.Header(), k)
		}

		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()

		// Copy the response body to the http.ResponseWriter
		_, err = io.Copy(w, resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}
