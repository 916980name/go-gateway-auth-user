package middleware

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"api-gateway/pkg/proxy"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type AuthRequirements struct {
	Privileges  string
	TokenSecret string
	PubKey      *rsa.PublicKey
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
					log.C(ctx).Warnw(fmt.Sprintf("auth failed verify: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				payload, ok := verifiedPayload.(map[string]interface{})
				if !ok {
					log.C(ctx).Warnw("auth failed get payload")
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				passed, err := checkPrivileges(authR.Privileges, payload)
				if !passed || err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed privilege: %s", err))
					return nil, NewHTTPError("Unauthorized", http.StatusUnauthorized)
				}
				// TODO: check token valid in cache
				// get user info
				user := payload["username"]
				if user == "" {
					log.C(ctx).Warnw("auth get user failed")
				}
				ctx = context.WithValue(ctx, common.Trace_request_user{}, user)
			}
			resp, err := next(ctx, r)
			log.C(ctx).Debugw("<-- AuthFilter do end <--")
			return resp, err
		}
	}
}

func getJWTTokenString(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("no Authorization header found")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("invalid Authorization header format")
	}

	return parts[1], nil
}

func checkPrivileges(routePrivileges string, verifiedPayload map[string]interface{}) (bool, error) {
	userPri := verifiedPayload["privileges"]
	if userPri == "" {
		return false, errors.New("user Privilege not found")
	}
	userPrivileges, ok := userPri.(string)
	if !ok {
		return false, errors.New("user Privilege parse failed")
	}

	routePArray := strings.Split(routePrivileges, ",")
	userPArray := strings.Split(userPrivileges, ",")
	for _, p := range routePArray {
		routeP := strings.TrimSpace(p)
		for _, up := range userPArray {
			userP := strings.TrimSpace(up)
			if userP == routeP {
				return true, nil
			}
		}
	}
	return false, fmt.Errorf("%w:%s", errors.New("unAllowed privileges"), userPrivileges)
}
