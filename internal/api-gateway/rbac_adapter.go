package gateway

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/rbac"
	"context"
	"net/http"
)

func rbacMiddlewareAdapter(rc *rbac.RBAC) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			ctx = mapContextToRBAC(ctx, r)

			var (
				respCtx  context.Context
				resp     *http.Response
				proxyErr error
				called   bool
			)

			inner := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				called = true
				respCtx, resp, proxyErr = next(req.Context(), req)
			})

			recorder := &statusRecorder{ResponseWriter: discardWriter{}}
			rc.Middleware(inner).ServeHTTP(recorder, r.WithContext(ctx))

			if !called {
				return ctx, nil, common.NewHTTPError(recorder.body, recorder.code)
			}
			return respCtx, resp, proxyErr
		}
	}
}

func mapContextToRBAC(ctx context.Context, r *http.Request) context.Context {
	if username, ok := ctx.Value(common.Trace_request_user{}).(string); ok && username != "" {
		ctx = context.WithValue(ctx, rbac.CtxKeyUsername, username)
	}
	if domain, ok := ctx.Value(common.Trace_request_domain{}).(string); ok && domain != "" {
		ctx = context.WithValue(ctx, rbac.CtxKeyDomain, domain)
	}
	return ctx
}

type statusRecorder struct {
	http.ResponseWriter
	code int
	body string
}

func (r *statusRecorder) WriteHeader(code int) {
	r.code = code
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	r.body = string(b)
	return len(b), nil
}

func (r *statusRecorder) Header() http.Header {
	return http.Header{}
}

type discardWriter struct{}

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(b []byte) (int, error)  { return len(b), nil }
func (discardWriter) WriteHeader(statusCode int)   {}
