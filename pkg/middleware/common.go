package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/proxy"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	HEADER_ACCESS_TOKEN  = "Authorization"
	HEADER_REFRESH_TOKEN = "Refresh"

	JWT_TOKEN_DEFAULT_TIMEOUT         = 24 * time.Hour
	JWT_REFRESH_TOKEN_DEFAULT_TIMEOUT = 120 * time.Hour
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

func generateTwoTokens(bodyBytes []byte, onlineCache *cache.CacheOper, priKey *rsa.PrivateKey) (string, string, error) {
	m := make(map[string]interface{})
	err := json.Unmarshal(bodyBytes, &m)
	if err != nil {
		return "", "", fmt.Errorf("LoginFilter read userinfo failed: error: %s", err)
	}
	token, err := jwt.GenerateJWTRSA(m, JWT_TOKEN_DEFAULT_TIMEOUT, priKey)
	if err != nil {
		return "", "", fmt.Errorf("LoginFilter gen token failed: error: %s", err)
	}
	// generate jwt refresh token
	md5bytes := md5.Sum([]byte(token))
	md5Str := string(md5bytes[:])
	refreshToken, err := jwt.GenerateJWTRSARefreshToken(md5Str, JWT_REFRESH_TOKEN_DEFAULT_TIMEOUT, priKey)
	if err != nil {
		return "", "", fmt.Errorf("LoginFilter gen refresh token failed: error: %s", err)
	}
	// save token to cache
	if onlineCache != nil {
		(*onlineCache).Set(getOnlineCacheKey(m["username"].(string)), md5Str)
	}
	return token, refreshToken, nil
}
