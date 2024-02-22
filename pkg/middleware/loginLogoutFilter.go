package middleware

import (
	"api-gateway/pkg/cache"
	"api-gateway/pkg/config"
	"api-gateway/pkg/log"
	"context"
	"fmt"
	"net/http"
)

type LoginLogoutRequirements struct {
	Cache *cache.CacheOper
	cfg   *config.LoginLogoutFilterConfig
}

func LoginLogoutFilter(pf GatewayHandlerFactory, l *LoginLogoutRequirements) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("LoginLogoutFilter do start")
			path := getRequestUri(r)
			switch path {
			case l.cfg.LoginPath:
				beginLoginHandle(ctx)
			case l.cfg.LogoutPath:
				beginLogoutHandle(ctx)
			default:
				log.C(ctx).Warnw(fmt.Sprintf("LoginLogoutFilter path not found: %s", path))
			}

			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("LoginLogoutFilter do end")
		}
	}
}

func beginLoginHandle(ctx context.Context) {

}

func beginLogoutHandle(ctx context.Context) {

}
