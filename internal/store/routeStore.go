package store

import (
	"api-gateway/internal/model"
	"context"

	"gorm.io/gorm"
)

type RouteStore interface {
	List(ctx context.Context, offset, limit int) (count int64, ret []*model.RouteModel, err error)
}

type routes struct {
	db *gorm.DB
}

// 确保 users 实现了 UserStore 接口.
var _ RouteStore = (*routes)(nil)

func newRoutes(db *gorm.DB) *routes {
	return &routes{db}
}

// List 根据 offset 和 limit 返回 user 列表.
func (r *routes) List(ctx context.Context, offset, limit int) (count int64, ret []*model.RouteModel, err error) {
	err = r.db.Offset(offset).Limit(limit).Order("id asc").Find(&ret).
		Offset(-1).
		Limit(-1).
		Count(&count).
		Error

	return
}
