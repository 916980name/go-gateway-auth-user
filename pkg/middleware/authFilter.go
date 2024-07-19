package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type AuthRequirements struct {
	Privileges  string
	TokenSecret string
	PubKey      *rsa.PublicKey
	PriKey      *rsa.PrivateKey
	OnlineCache *cache.CacheOper
}

type GeneralUserInfo struct {
	Username   string `json:"username"`
	Privileges string `json:"privileges"`
	IdKey      string `json:"idKey"`
}

func AuthFilter(authR AuthRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (context.Context, *http.Response, error) {
			log.C(ctx).Debugw("--> AuthFilter do start -->")
			if authR.Privileges != "" {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				verifiedPayload, err := jwt.VerifyJWTRSA(token, authR.PubKey)
				if err != nil {
					u, _ := getUserInfoFromPayload(ctx, verifiedPayload)
					if u != nil {
						ctx = contextSetUserInfo(ctx, u)
					}
					log.C(ctx).Warnw(fmt.Sprintf("auth failed verify: %s", err))
					return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				userInfo, err := getUserInfoFromPayload(ctx, verifiedPayload)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed marsh payload: %s", err))
					return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				ctx = contextSetUserInfo(ctx, userInfo)
				// check privilege
				passed, err := checkPrivileges(authR.Privileges, *userInfo)
				if !passed || err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed privilege: %s", err))
					return ctx, nil, common.NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				// check token valid in cache
				if authR.OnlineCache != nil {
					md5str, err := (*authR.OnlineCache).Get(ctx, getOnlineCacheKey(userInfo.Username))
					if err != nil || md5str == "" {
						return ctx, nil, common.NewHTTPError("Unauthorized, Please login", http.StatusUnauthorized)
					}
					cacheMd5Str := common.StringToMD5Base64(token)
					if md5str != cacheMd5Str {
						return ctx, nil, common.NewHTTPError("Unauthorized, Please login again", http.StatusUnauthorized)
					}
				}
			}
			ctx, resp, err := next(ctx, r)

			log.C(ctx).Debugw("<-- AuthFilter do end <--")
			return ctx, resp, err
		}
	}
}

func contextSetUserInfo(ctx context.Context, userInfo *GeneralUserInfo) context.Context {
	ctx = context.WithValue(ctx, common.Trace_request_user{}, userInfo.Username)
	ctx = context.WithValue(ctx, common.Trace_request_uid{}, userInfo.IdKey)
	return ctx
}

func getUserInfoFromPayload(ctx context.Context, payload interface{}) (*GeneralUserInfo, error) {
	userinfo := GeneralUserInfo{}
	if payload == nil {
		return nil, fmt.Errorf("no payload")
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(bodyBytes), &userinfo)
	return &userinfo, nil
}

func getJWTTokenString(r *http.Request) (string, error) {
	authHeader := r.Header.Get(HEADER_ACCESS_TOKEN)
	if authHeader == "" {
		// try to read from cookie
		cookie, err := r.Cookie(HEADER_ACCESS_TOKEN)
		if err != nil {
			return "", errors.New("no Authorization header found")
		}
		authHeader = fmt.Sprintf("Bearer %s", cookie.Value)
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid Authorization header format")
	}

	return parts[1], nil
}

func getJWTRefreshTokenString(r *http.Request) (string, error) {
	authHeader := r.Header.Get(HEADER_REFRESH_TOKEN)
	if authHeader == "" {
		cookie, err := r.Cookie(HEADER_REFRESH_TOKEN)
		if err != nil {
			return "", errors.New("no refresh header found")
		}
		authHeader = cookie.Value
	}
	return authHeader, nil
}

func checkPrivileges(routePrivileges string, userInfo GeneralUserInfo) (bool, error) {
	userPri := userInfo.Privileges
	if userPri == "" {
		return false, errors.New("user Privilege not found")
	}

	routePArray := strings.Split(routePrivileges, ",")
	userPArray := strings.Split(userPri, ",")
	for _, p := range routePArray {
		routeP := strings.TrimSpace(p)
		for _, up := range userPArray {
			userP := strings.TrimSpace(up)
			if userP == routeP {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("%w:%s", errors.New("unAllowed "), userPri)
}
