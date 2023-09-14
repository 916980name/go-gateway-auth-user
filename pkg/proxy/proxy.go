package proxy

import (
	"api-gateway/pkg/common"
	"context"
	"net/http"
)

var defaultHTTPClient = &http.Client{}

func NewHTTPProxyDetailed(backend string) func(ctx context.Context, r *http.Request) (*http.Response, error) {
	return func(ctx context.Context, r *http.Request) (*http.Response, error) {
		r.URL.Host = backend
		r.RequestURI = ""
		r.URL.Scheme = "http"
		addTraceHeader(ctx, r)
		resp, err := defaultHTTPClient.Do(r.WithContext(ctx))

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if err != nil {
			return nil, err
		}
		return resp, err
	}
}

func addTraceHeader(ctx context.Context, r *http.Request) {
	if requestID := ctx.Value(common.REQUEST_ID); requestID != nil {
		if str, ok := requestID.(string); ok {
			r.Header.Add(common.REQUEST_ID, str)
		}
	}
	if resourceIP := ctx.Value(common.RESOURCE_IP); resourceIP != nil {
		if str, ok := resourceIP.(string); ok {
			r.Header.Add(common.RESOURCE_IP, str)
		}
	}
	if requestUri := ctx.Value(common.REQUEST_URI); requestUri != nil {
		if str, ok := requestUri.(string); ok {
			r.Header.Add(common.REQUEST_URI, str)
		}
	}
	if method := ctx.Value(common.REQUEST_METHOD); method != nil {
		if str, ok := method.(string); ok {
			r.Header.Add(common.REQUEST_METHOD, str)
		}
	}
}
