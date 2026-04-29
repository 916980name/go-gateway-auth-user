package handler

import (
	"net/http"

	"api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
)

type PaginationConfig struct {
	DefaultPageSize int
	MaxPageSize     int
}

type TenantHandler struct {
	repo     *store.TenantRepo
	pgCfg    PaginationConfig
	onChange func()
}

func NewTenantHandler(repo *store.TenantRepo, pgCfg PaginationConfig, onChange func()) *TenantHandler {
	return &TenantHandler{repo: repo, pgCfg: pgCfg, onChange: onChange}
}

type createTenantRequest struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

type updateTenantRequest struct {
	Name     *string `json:"name"`
	Hostname *string `json:"hostname"`
}

func (h *TenantHandler) List(w http.ResponseWriter, r *http.Request) {
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.List(r.Context(), p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *TenantHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createTenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.Code == "" || req.Name == "" || req.Hostname == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "code, name, and hostname are required")
		return
	}
	t := &store.Tenant{Code: req.Code, Name: req.Name, Hostname: req.Hostname}
	if err := h.repo.Create(r.Context(), t); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	writeJSON(w, http.StatusCreated, t)
}

func (h *TenantHandler) Get(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	t, err := h.repo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *TenantHandler) Update(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	var req updateTenantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	t, err := h.repo.Update(r.Context(), uid, req.Name, req.Hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	writeJSON(w, http.StatusOK, t)
}

func (h *TenantHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	if err := h.repo.SoftDelete(r.Context(), uid); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	w.WriteHeader(http.StatusNoContent)
}
