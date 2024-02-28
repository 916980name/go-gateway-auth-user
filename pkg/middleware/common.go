package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/proxy"
	"context"
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

func generateAccessToken(ctx context.Context, bodyBytes []byte, onlineCache *cache.CacheOper, priKey *rsa.PrivateKey) (string, error) {
	m := make(map[string]interface{})
	err := json.Unmarshal(bodyBytes, &m)
	if err != nil {
		return "", fmt.Errorf("LoginFilter read userinfo failed: error: %s", err)
	}
	token, err := jwt.GenerateJWTRSA(m, JWT_TOKEN_DEFAULT_TIMEOUT, priKey)
	if err != nil {
		return "", fmt.Errorf("LoginFilter gen token failed: error: %s", err)
	}
	// save token to cache
	md5Str := common.StringToMD5Base64(token)
	if onlineCache != nil {
		(*onlineCache).Set(ctx, getOnlineCacheKey(m["username"].(string)), md5Str)
	}
	return token, nil
}

func generateTwoTokens(ctx context.Context, bodyBytes []byte, onlineCache *cache.CacheOper, priKey *rsa.PrivateKey) (string, string, error) {
	token, err := generateAccessToken(ctx, bodyBytes, onlineCache, priKey)
	if err != nil {
		return "", "", err
	}
	// generate jwt refresh token
	md5Str := common.StringToMD5Base64(token)
	refreshToken, err := jwt.GenerateJWTRSARefreshToken(md5Str, JWT_REFRESH_TOKEN_DEFAULT_TIMEOUT, priKey)
	if err != nil {
		return "", "", fmt.Errorf("LoginFilter gen refresh token failed: error: %s", err)
	}
	return token, refreshToken, nil
}
