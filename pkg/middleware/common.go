package middleware

import (
	"api-gateway/pkg/proxy"
	"context"
	"fmt"
	"net/http"
)

func Middleware(name string) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, req *http.Request) (*http.Response, error) {

			resp, err := next(ctx, req)

			return resp, err
		}
	}
}

type HTTPError struct {
	Msg    string
	Status int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%d %s", e.Status, e.Msg)
}

func NewHTTPError(msg string, status int) *HTTPError {
	return &HTTPError{
		Msg:    msg,
		Status: status,
	}
}
