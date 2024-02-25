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
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
			log.C(ctx).Debugw("--> RequestFilter do start -->")
			ip := getClientIP(r)
			ctx = context.WithValue(ctx, common.Trace_request_ip{}, ip)

			rId := getRequestId(r)
			ctx = context.WithValue(ctx, common.Trace_request_id{}, rId)

			ctx = context.WithValue(ctx, common.Trace_request_uri{}, getRequestUri(r))
			ctx = context.WithValue(ctx, common.Trace_request_method{}, getRequestMethod(r))
			ctx = context.WithValue(ctx, common.Trace_request_domain{}, getRequestDomain(r))
			// TODO get timezone
			resp, err := next(ctx, r)
			log.C(ctx).Debugw("<-- RequestFilter do end <--")
			return resp, err
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

func getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// The client IP may be a comma-separated list, get the first IP
		ips := strings.Split(xff, ",")
		ip := strings.TrimSpace(ips[0])
		return ip
	}

	// Check for X-Real-IP header
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return xrip
	}

	// If headers not found, use RemoteAddr as fallback
	ip := r.RemoteAddr

	// If the IP address contains a port number, remove it
	// {"ip": "[::1]:46158"}
	lastColon := strings.LastIndex(ip, ":")
	if lastColon != -1 {
		ip = strings.TrimRight(ip[:lastColon], ":")
	}

	return ip
}
