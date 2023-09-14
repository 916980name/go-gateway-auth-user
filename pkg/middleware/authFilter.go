package middleware

import (
	"api-gateway/pkg/log"
	"context"
	"net/http"
)

func AuthFilter(pf GatewayHandlerFactory) GatewayHandlerFactory {
	return func(next GatewayContextHandlerFunc) GatewayContextHandlerFunc {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request) {
			log.C(ctx).Infow("auth do start")
			if pf != nil {
				next = pf(next)
			}
			next(ctx, w, r)
			log.C(ctx).Infow("auth do end")
		}
	}
}
