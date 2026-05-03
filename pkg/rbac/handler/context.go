package handler

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

type ctxKey struct{ name string }

var (
	ctxTenantUUID = &ctxKey{"handler-tenant-uuid"}
)

func TenantUUIDFromCtx(ctx context.Context) (uuid.UUID, error) {
	if v, ok := ctx.Value(ctxTenantUUID).(string); ok && v != "" {
		return uuid.Parse(v)
	}
	return uuid.Nil, fmt.Errorf("tenant uuid not found in context")
}

func SetTenantUUIDInCtx(ctx context.Context, uid string) context.Context {
	return context.WithValue(ctx, ctxTenantUUID, uid)
}
