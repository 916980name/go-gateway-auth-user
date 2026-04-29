package handler

import (
	"net/http"

	"api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
)

type RoleHandler struct {
	repo          *store.RoleRepo
	pgCfg         PaginationConfig
	onPolicyChange func()
}

func NewRoleHandler(repo *store.RoleRepo, pgCfg PaginationConfig, onPolicyChange func()) *RoleHandler {
	return &RoleHandler{repo: repo, pgCfg: pgCfg, onPolicyChange: onPolicyChange}
}

type createRoleRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateRoleRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type setRolesRequest struct {
	RoleUUIDs []uuid.UUID `json:"roleUuids"`
}

func (h *RoleHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.ListByTenant(r.Context(), tenantUID, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *RoleHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	var req createRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.Code == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "code and name are required")
		return
	}
	role := &store.Role{Code: req.Code, Name: req.Name, Description: req.Description}
	if err := h.repo.Create(r.Context(), tenantUID, role); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, role)
}

func (h *RoleHandler) Update(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid role uuid")
		return
	}
	var req updateRoleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	role, err := h.repo.Update(r.Context(), uid, req.Name, req.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (h *RoleHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid role uuid")
		return
	}
	if err := h.repo.Delete(r.Context(), uid); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RoleHandler) GetUserRoles(w http.ResponseWriter, r *http.Request) {
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	userUID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid user uuid")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.GetUserRolesInTenant(r.Context(), tenantUID, userUID, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *RoleHandler) SetUserRoles(w http.ResponseWriter, r *http.Request) {
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	userUID, err := uuid.Parse(r.PathValue("userId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid user uuid")
		return
	}
	var req setRolesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if err := h.repo.SetUserRoles(r.Context(), tenantUID, userUID, req.RoleUUIDs); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}
	w.WriteHeader(http.StatusNoContent)
}
