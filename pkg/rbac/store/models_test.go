package store

import (
	"testing"
)

func TestPaginationParams(t *testing.T) {
	p := PaginationParams{Page: 1, PageSize: 20}
	if p.Page != 1 {
		t.Errorf("expected page 1, got %d", p.Page)
	}
	if p.PageSize != 20 {
		t.Errorf("expected pageSize 20, got %d", p.PageSize)
	}
}

func TestPaginatedResult(t *testing.T) {
	result := PaginatedResult[User]{
		Data: []User{{Username: "alice"}},
		Pagination: Pagination{
			Page:     1,
			PageSize: 20,
			Total:    1,
		},
	}
	if len(result.Data) != 1 {
		t.Errorf("expected 1 item, got %d", len(result.Data))
	}
	if result.Data[0].Username != "alice" {
		t.Errorf("expected username alice, got %s", result.Data[0].Username)
	}
}
