package middleware

import (
	"api-gateway/pkg/common"
	"context"
	"net/http"
	"strings"
)

func RequestFilter(ctx context.Context, next func(context.Context, http.ResponseWriter, *http.Request)) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if ctx == nil {
			ctx = context.Background()
		}
		ip := getClientIP(r)
		ctx = context.WithValue(ctx, common.RESOURCE_IP, ip)

		rId := getRequestId(r)
		ctx = context.WithValue(ctx, common.REQUEST_ID, rId)

		ctx = context.WithValue(ctx, common.REQUEST_URI, getRequestUri(r))
		ctx = context.WithValue(ctx, common.REQUEST_METHOD, getRequestMethod(r))
		next(ctx, w, r)
	}
}

func getRequestUri(r *http.Request) string {
	return r.URL.Path
}

func getRequestMethod(r *http.Request) string {
	return r.Method
}

func getRequestId(r *http.Request) string {
	return r.Header.Get(common.REQUEST_ID)
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
	if index := strings.IndexByte(ip, ':'); index >= 0 {
		ip = ip[:index]
	}

	return ip
}
