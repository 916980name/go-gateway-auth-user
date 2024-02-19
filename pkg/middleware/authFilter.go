package middleware

import (
	"api-gateway/pkg/log"
	"context"
	"net/http"
)

func AuthFilter(pf GatewayHandlerFactory, privileges string) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Debugw("auth do start")
			if privileges != "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Debugw("auth do end")
		}
	}
}
