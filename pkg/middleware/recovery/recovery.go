package recovery

import (
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"context"
	"fmt"
	"net/http"
	"runtime"
)

type HandlerFunc func(ctx context.Context, req *http.Request, err interface{})

type options struct {
	handler HandlerFunc
}

type Option func(*options)

func WithHandler(h HandlerFunc) Option {
	return func(o *options) {
		o.handler = h
	}
}

func Recovery(opts ...Option) proxy.Middleware {
	op := options{
		handler: func(ctx context.Context, req *http.Request, err interface{}) {

		},
	}
	for _, o := range opts {
		o(&op)
	}
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			defer func() {
				if rerr := recover(); rerr != nil {
					buf := make([]byte, 64<<10)
					n := runtime.Stack(buf, false)
					buf = buf[:n]
					log.C(ctx).Errorw(fmt.Sprintf("%v: \n%s\n", rerr, buf), "error", string(buf))
					op.handler(ctx, r, rerr)
				}
			}()
			return next(ctx, r)
		}
	}
}
