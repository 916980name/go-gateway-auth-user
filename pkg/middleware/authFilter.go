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

func AuthFilter(pf GatewayHandlerFactory, authR AuthRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w *proxy.CustomResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("--> AuthFilter do start -->")
			if authR.Privileges != "" {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				verifiedPayload, err := jwt.VerifyJWTRSA(token, authR.PubKey)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed verify: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				payload, ok := verifiedPayload.(map[string]interface{})
				if !ok {
					log.C(ctx).Warnw("auth failed get payload")
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				passed, err := checkPrivileges(authR.Privileges, payload)
				if !passed || err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed privilege: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				// TODO: check token valid in cache
				// get user info
				user := payload["username"]
				if user == "" {
					log.C(ctx).Warnw("auth get user failed")
				}
				ctx = context.WithValue(ctx, common.Trace_request_user{}, user)
			}
			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("<-- AuthFilter do end <--")
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
