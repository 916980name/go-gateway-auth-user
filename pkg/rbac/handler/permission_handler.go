package handler

import (
	"net/http"

	"api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
)

type PermissionHandler struct {
	repo           *store.PermissionRepo
	pgCfg          PaginationConfig
	onPolicyChange func()
}

func NewPermissionHandler(repo *store.PermissionRepo, pgCfg PaginationConfig, onPolicyChange func()) *PermissionHandler {
	return &PermissionHandler{repo: repo, pgCfg: pgCfg, onPolicyChange: onPolicyChange}
}

type createPermissionRequest struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
	Description string `json:"description"`
}

type updatePermissionRequest struct {
	Name        *string `json:"name"`
	Resource    *string `json:"resource"`
	Action      *string `json:"action"`
	Description *string `json:"description"`
}

type setPermissionsRequest struct {
	PermissionUUIDs []uuid.UUID `json:"permissionUuids"`
}

func (h *PermissionHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := TenantUUIDFromCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.ListByTenant(r.Context(), tenantUUID, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *PermissionHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := TenantUUIDFromCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	var req createPermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.Code == "" || req.Name == "" || req.Resource == "" || req.Action == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "code, name, resource, and action are required")
		return
	}
	perm := &store.Permission{Code: req.Code, Name: req.Name, Resource: req.Resource, Action: req.Action, Description: req.Description}
	if err := h.repo.Create(r.Context(), tenantUUID, perm); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, perm)
}

func (h *PermissionHandler) Update(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid permission uuid")
		return
	}
	var req updatePermissionRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	perm, err := h.repo.Update(r.Context(), uid, req.Name, req.Resource, req.Action, req.Description)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}
	writeJSON(w, http.StatusOK, perm)
}

func (h *PermissionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid permission uuid")
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

func (h *PermissionHandler) GetRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid role uuid")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.GetRolePermissions(r.Context(), roleUID, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *PermissionHandler) SetRolePermissions(w http.ResponseWriter, r *http.Request) {
	roleUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid role uuid")
		return
	}
	var req setPermissionsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if err := h.repo.SetRolePermissions(r.Context(), roleUID, req.PermissionUUIDs); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onPolicyChange != nil {
		h.onPolicyChange()
	}
	w.WriteHeader(http.StatusNoContent)
}
