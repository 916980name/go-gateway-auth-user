package handler

import (
	"net/http"

	"api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
)

type UserHandler struct {
	repo  *store.UserRepo
	pgCfg PaginationConfig
}

func NewUserHandler(repo *store.UserRepo, pgCfg PaginationConfig) *UserHandler {
	return &UserHandler{repo: repo, pgCfg: pgCfg}
}

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
}

type updateUserRequest struct {
	DisplayName *string `json:"displayName"`
	Email       *string `json:"email"`
	Phone       *string `json:"phone"`
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	search := r.URL.Query().Get("search")
	result, err := h.repo.List(r.Context(), p, search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "username is required")
		return
	}
	u := &store.User{Username: req.Username, DisplayName: req.DisplayName, Email: req.Email, Phone: req.Phone}
	if err := h.repo.Create(r.Context(), u); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	u, err := h.repo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	var req updateUserRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	u, err := h.repo.Update(r.Context(), uid, req.DisplayName, req.Email, req.Phone)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	if err := h.repo.SoftDelete(r.Context(), uid); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) ListTenants(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	result, err := h.repo.ListTenants(r.Context(), uid, p)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *UserHandler) AddToTenant(w http.ResponseWriter, r *http.Request) {
	userUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid user uuid")
		return
	}
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	if err := h.repo.AddToTenant(r.Context(), userUID, tenantUID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *UserHandler) RemoveFromTenant(w http.ResponseWriter, r *http.Request) {
	userUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid user uuid")
		return
	}
	tenantUID, err := uuid.Parse(r.PathValue("tenantId"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	if err := h.repo.RemoveFromTenant(r.Context(), userUID, tenantUID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
