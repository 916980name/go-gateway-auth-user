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
	if requestID := ctx.Value(common.Trace_request_id{}); requestID != nil {
		if str, ok := requestID.(string); ok {
			r.Header.Add(common.REQUEST_ID, str)
		}
	}
	if resourceIP := ctx.Value(common.Trace_request_ip{}); resourceIP != nil {
		if str, ok := resourceIP.(string); ok {
			r.Header.Add(common.RESOURCE_IP, str)
		}
	}
	if requestUri := ctx.Value(common.Trace_request_uri{}); requestUri != nil {
		if str, ok := requestUri.(string); ok {
			r.Header.Add(common.REQUEST_URI, str)
		}
	}
	if method := ctx.Value(common.Trace_request_method{}); method != nil {
		if str, ok := method.(string); ok {
			r.Header.Add(common.REQUEST_METHOD, str)
		}
	}
	if user := ctx.Value(common.Trace_request_user{}); user != nil {
		if str, ok := user.(string); ok {
			r.Header.Add(common.REQUEST_USER, str)
		}
	}
	// TODO timezone
}
