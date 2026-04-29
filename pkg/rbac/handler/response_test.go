package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteJSON(t *testing.T) {
	w := httptest.NewRecorder()
	data := map[string]string{"key": "value"}
	writeJSON(w, http.StatusOK, data)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	var result map[string]string
	json.NewDecoder(w.Body).Decode(&result)
	if result["key"] != "value" {
		t.Errorf("expected value, got %s", result["key"])
	}
}

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "INVALID_INPUT", "missing field")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", w.Code)
	}
	var result ErrorResponse
	json.NewDecoder(w.Body).Decode(&result)
	if result.Error.Code != "INVALID_INPUT" {
		t.Errorf("expected INVALID_INPUT, got %s", result.Error.Code)
	}
	if result.Error.Message != "missing field" {
		t.Errorf("expected 'missing field', got %s", result.Error.Message)
	}
}

func TestParsePagination(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		defSize  int
		maxSize  int
		wantPage int
		wantSize int
	}{
		{"defaults", "", 20, 100, 1, 20},
		{"custom", "page=3&pageSize=50", 20, 100, 3, 50},
		{"capped", "page=1&pageSize=500", 20, 100, 1, 100},
		{"negative page", "page=-1&pageSize=10", 20, 100, 1, 10},
		{"zero pageSize", "page=1&pageSize=0", 20, 100, 1, 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/?"+tt.query, nil)
			p := parsePagination(r, tt.defSize, tt.maxSize)
			if p.Page != tt.wantPage {
				t.Errorf("page: got %d, want %d", p.Page, tt.wantPage)
			}
			if p.PageSize != tt.wantSize {
				t.Errorf("pageSize: got %d, want %d", p.PageSize, tt.wantSize)
			}
		})
	}
}
