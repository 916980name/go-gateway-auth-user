package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"api-gateway/pkg/util"
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
)

func NewRefreshTokenHandler(onlineCache *cache.CacheOper, pubKey *rsa.PublicKey, priKey *rsa.PrivateKey, cookieEnabled bool) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			// use refresh token, generate new access token
			token, err := getJWTTokenString(r)
			if err != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler", "error", err)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			verifiedPayload, err := jwt.VerifyJWTRSA(token, pubKey)
			u, uerr := getUserInfoFromPayload(ctx, verifiedPayload)
			if uerr != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler get userinfo failed", "error", uerr)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			ctx = contextSetUserInfo(ctx, u)
			if err != nil && strings.Contains(err.Error(), jwtv5.ErrTokenExpired.Error()) {
				log.C(ctx).Infow("NewRefreshTokenHandler Refresh an Expired token")
			} else {
				log.C(ctx).Infow("NewRefreshTokenHandler Refresh token", "error", err)
			}
			refreshToken, err := getJWTRefreshTokenString(r)
			if err != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler refresh token failed", "error", err)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			refreshPayload, err := jwt.VerifyJWTRSA(refreshToken, pubKey)
			if err != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler refresh token verify failed", "error", err)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			ru, uerr := getUserInfoFromPayload(ctx, refreshPayload)
			if uerr != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler get userinfo from refresh token failed", "error", uerr)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			ctx = contextSetUserInfo(ctx, ru)
			// check
			if u.IdKey != ru.IdKey || u.Username != ru.Username {
				log.C(ctx).Errorw("userinfo not match", "IdKey", u.IdKey, "refresh_IdKey", ru.IdKey,
					"Username", u.Username, "refresh_Username", ru.Username)
				return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
			}
			// refresh token valid, generate new tokens
			bodyBytes, err := json.Marshal(u)
			if err != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler read userinfo failed", "error", err)
				return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
			}
			token, err = generateAccessToken(ctx, bodyBytes, onlineCache, priKey)
			if err != nil {
				log.C(ctx).Errorw("NewRefreshTokenHandler generate new token failed", "error", err)
				return ctx, nil, common.NewHTTPError("", http.StatusInternalServerError)
			}
			log.C(ctx).Infow(fmt.Sprintf("NewRefreshTokenHandler refresh token for: %s", u.Username))
			resp := &http.Response{
				Status:     "200 OK",
				StatusCode: 200,
				Proto:      "HTTP/1.1",
				ProtoMajor: 1,
				ProtoMinor: 1,
				Header: http.Header{
					HEADER_ACCESS_TOKEN: {token},
				},
				Request:       r,
				Close:         true,
				ContentLength: -1,
				Body:          io.NopCloser(bytes.NewReader([]byte{})),
			}
			if cookieEnabled {
				tokenTO := time.Now().Add(JWT_TOKEN_DEFAULT_TIMEOUT)
				util.ResponseSetRootCookie(resp, HEADER_ACCESS_TOKEN, token, &tokenTO)
			}

			return ctx, resp, nil
		}
	}
}
