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

	for _, site := range sites {
		for _, item := range site.Routes {
			counter.Add(1)
			newR := r.Host(site.HostName).Name(fmt.Sprint(counter.Load()))
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

			chain := handleMuxChain(backend)
			if item.Privilege != "" {
				chain = middleware.AuthFilter(chain, item.Privilege)
			}
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
		log.C(ctx).Infow(fmt.Sprint(resp.StatusCode))

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
