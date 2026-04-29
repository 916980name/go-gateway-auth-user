package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"api-gateway/pkg/rbac/store"
)

type ErrorResponse struct {
	Error ErrorBody `json:"error"`
}

type ErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, ErrorResponse{
		Error: ErrorBody{Code: code, Message: message},
	})
}

func parsePagination(r *http.Request, defaultSize, maxSize int) store.PaginationParams {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("pageSize"))
	if pageSize < 1 {
		pageSize = defaultSize
	}
	if pageSize > maxSize {
		pageSize = maxSize
	}
	return store.PaginationParams{Page: page, PageSize: pageSize}
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}
