package handler

import (
	"net/http"

	"api-gateway/pkg/common"
)

type PaginationConfig = common.PaginationConfig
type ErrorResponse = common.ErrorResponse

func writeJSON(w http.ResponseWriter, status int, data any) {
	common.WriteJSON(w, status, data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	common.WriteError(w, status, code, message)
}

func parsePagination(r *http.Request, defaultSize, maxSize int) common.PaginationParams {
	return common.ParsePagination(r, defaultSize, maxSize)
}

func decodeJSON(r *http.Request, v any) error {
	return common.DecodeJSON(r, v)
}
