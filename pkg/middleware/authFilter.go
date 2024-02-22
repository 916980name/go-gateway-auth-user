package middleware

import (
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type AuthRequirements struct {
	Privileges  string
	TokenSecret string
}

func AuthFilter(pf GatewayHandlerFactory, authR AuthRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("auth do start")
			if authR.Privileges != "" {
				token, err := getJWTTokenString(r)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed token: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				verifiedPayload, err := jwt.VerifyJWT(token, authR.TokenSecret)
				if err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed verify: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				passed, err := checkPrivileges(authR.Privileges, verifiedPayload)
				if !passed || err != nil {
					log.C(ctx).Warnw(fmt.Sprintf("auth failed privilege: %s", err))
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
				// get user info
				user := verifiedPayload["username"]
				if user == "" {
					log.C(ctx).Warnw("auth get user failed")
				}
				ctx = context.WithValue(ctx, common.Trace_request_user{}, user)
			}
			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("auth do end")
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

func checkPrivileges(privileges string, verifiedPayload map[string]interface{}) (bool, error) {
	role := verifiedPayload["role"]
	if role == "" {
		return false, errors.New("role not found")
	}
	pArray := strings.Split(privileges, ",")
	for _, p := range pArray {
		privilege := strings.TrimSpace(p)
		if role == privilege {
			return true, nil
		}
	}
	return false, fmt.Errorf("%w:%s", errors.New("unAllowed role"), role)
}