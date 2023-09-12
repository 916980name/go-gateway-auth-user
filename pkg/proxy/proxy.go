package proxy

import (
	"context"
	"net/http"
)

var defaultHTTPClient = &http.Client{}
var backend = "127.0.0.1:8081"

func NewHTTPProxyDetailed() func(ctx context.Context, r *http.Request) (*http.Response, error) {
	return func(ctx context.Context, r *http.Request) (*http.Response, error) {
		r.URL.Host = backend
		r.RequestURI = ""
		r.URL.Scheme = "http"
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
