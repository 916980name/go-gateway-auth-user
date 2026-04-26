package middleware

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

func RequestFilter() proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			log.C(ctx).Debugw("--> RequestFilter do start -->")
			ip := getClientIP(r)
			ctx = context.WithValue(ctx, common.Trace_request_ip{}, ip)

			rId := getRequestId(r)
			ctx = context.WithValue(ctx, common.Trace_request_id{}, rId)

			ctx = context.WithValue(ctx, common.Trace_request_uri{}, getRequestUri(r))
			ctx = context.WithValue(ctx, common.Trace_request_method{}, getRequestMethod(r))
			ctx = context.WithValue(ctx, common.Trace_request_domain{}, getRequestDomain(r))
			ctx = context.WithValue(ctx, common.Trace_request_timezone{}, getRequestTimeZone(r))
			ctx, resp, err := next(ctx, r)
			log.C(ctx).Debugw("<-- RequestFilter do end <--")
			return ctx, resp, err
		}
	}
}

func getRequestDomain(r *http.Request) string {
	host := r.Host
	lastColon := strings.LastIndex(host, ":")
	if lastColon != -1 {
		host = strings.TrimRight(host[:lastColon], ":")
	}
	return host
}

func getRequestUri(r *http.Request) string {
	return r.URL.Path
}

func getRequestMethod(r *http.Request) string {
	return r.Method
}

func getRequestId(r *http.Request) string {
	requestID := r.Header.Get(common.REQUEST_ID)
	if requestID == "" {
		requestID = uuid.New().String()
	}
	return requestID
}

func getRequestTimeZone(r *http.Request) string {
	tz := r.Header.Get(common.REQUEST_TIMEZONE)
	return tz
}

func getClientIP(r *http.Request) string {
	ip := r.RemoteAddr
	lastColon := strings.LastIndex(ip, ":")
	if lastColon != -1 {
		ip = strings.TrimRight(ip[:lastColon], ":")
	}
	return ip
}
