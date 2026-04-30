package store

import (
	"testing"

	"api-gateway/pkg/common"
)

func TestPaginationParams(t *testing.T) {
	p := common.PaginationParams{Page: 1, PageSize: 20}
	if p.Page != 1 {
		t.Errorf("expected page 1, got %d", p.Page)
	}
	if p.PageSize != 20 {
		t.Errorf("expected pageSize 20, got %d", p.PageSize)
	}
}

func TestPaginatedResult(t *testing.T) {
	result := common.PaginatedResult[Role]{
		Data: []Role{{Code: "admin", Name: "Admin"}},
		Pagination: common.Pagination{
			Page:     1,
			PageSize: 20,
			Total:    1,
		},
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 item, got %d", len(result.Data))
	}
	if result.Data[0].Code != "admin" {
		t.Errorf("expected code admin, got %s", result.Data[0].Code)
	}
}
