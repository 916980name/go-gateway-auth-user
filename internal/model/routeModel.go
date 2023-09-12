package model

type RouteModel struct {
	ID        int64  `gorm:"column:id;primary_key"`
	Path      string `gorm:"column:path;not null"`
	Method    string `gorm:"column:method"`
	Route     string `gorm:"column:route;not null"`
	Privilege string `gorm:"column:privilege"`
}

// MySQL 表名
func (u *RouteModel) TableName() string {
	return "api_route"
}
