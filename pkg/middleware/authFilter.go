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
}

func AuthFilter(authR AuthRequirements) proxy.Middleware {
	return func(next proxy.Proxy) proxy.Proxy {
		return func(ctx context.Context, r *http.Request) (*http.Response, error) {
			log.C(ctx).Debugw("--> AuthFilter do start -->")
			if authR.Privileges != "" {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				verifiedPayload, err := jwt.VerifyJWTRSA(token, authR.PubKey)
				if err != nil {
					u, _ := getUserInfoFromPayload(ctx, verifiedPayload)
					ctx = context.WithValue(ctx, common.Trace_request_user{}, u.Username)
					log.C(ctx).Warnw(fmt.Sprintf("auth failed verify: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				userInfo, err := getUserInfoFromPayload(ctx, verifiedPayload)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed marsh payload: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				ctx = context.WithValue(ctx, common.Trace_request_user{}, userInfo.Username)
				// check privilege
				passed, err := checkPrivileges(authR.Privileges, *userInfo)
				if !passed || err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed privilege: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				// check token valid in cache
				if authR.OnlineCache != nil {
					md5str, err := (*authR.OnlineCache).Get(getOnlineCacheKey(userInfo.Username))
					if err != nil || md5str == "" {
						return nil, NewHTTPError("Unauthorized, Please login", http.StatusUnauthorized)
					}
					cacheMd5Str := common.StringToMD5Base64(token)
					if md5str != cacheMd5Str {
						return nil, NewHTTPError("Unauthorized, Please login again", http.StatusUnauthorized)
					}
				}
			}
			resp, err := next(ctx, r)

			log.C(ctx).Debugw("<-- AuthFilter do end <--")
			return resp, err
		}
	}
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
		return "", errors.New("no Authorization header found")
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
		return "", errors.New("no refresh header found")
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
