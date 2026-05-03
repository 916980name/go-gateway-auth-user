package handler

import (
	"net/http"
	"strconv"

	"api-gateway/pkg/rbac/handler"
	"api-gateway/pkg/user/store"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type UserHandler struct {
	userRepo   *store.UserRepo
	credRepo   *store.CredentialRepo
	tenantRepo *store.TenantRepo
	pgCfg      PaginationConfig
}

func NewUserHandler(userRepo *store.UserRepo, credRepo *store.CredentialRepo, tenantRepo *store.TenantRepo, pgCfg PaginationConfig) *UserHandler {
	return &UserHandler{userRepo: userRepo, credRepo: credRepo, tenantRepo: tenantRepo, pgCfg: pgCfg}
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

// userResponse excludes tenant_id and tenant_uuid from API responses
type userResponse struct {
	UUID        string `json:"uuid"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	Status      int16  `json:"status"`
}

func toUserResponse(u *store.User) userResponse {
	return userResponse{
		UUID:        u.UUID.String(),
		Username:    u.Username,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		Phone:       u.Phone,
		Status:      u.Status,
	}
}

func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := handler.TenantUUIDFromCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "tenant not resolved from domain")
		return
	}
	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}
	p := parsePagination(r, h.pgCfg.DefaultPageSize, h.pgCfg.MaxPageSize)
	search := r.URL.Query().Get("search")
	result, err := h.userRepo.List(r.Context(), tenant.ID, p, search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	// Convert to response struct that excludes tenant info
	items := make([]userResponse, len(result.Data))
	for i, u := range result.Data {
		items[i] = toUserResponse(&u)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"items": items,
		"total": result.Pagination.Total,
	})
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
	tenantUUID, err := handler.TenantUUIDFromCtx(r.Context())
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "tenant not resolved from domain")
		return
	}
	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}
	u := &store.User{
		TenantID:    tenant.ID,
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Email:       req.Email,
		Phone:       req.Phone,
	}
	if err := h.userRepo.Create(r.Context(), u); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, toUserResponse(u))
}

func (h *UserHandler) Get(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	u, err := h.userRepo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(u))
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
	u, err := h.userRepo.Update(r.Context(), uid, req.DisplayName, req.Email, req.Phone)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toUserResponse(u))
}

func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	if err := h.userRepo.SoftDelete(r.Context(), uid); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type createCredentialRequest struct {
	ProviderType string `json:"providerType"`
	Credential   string `json:"credential"`
	Identifier   string `json:"identifier"`
}

func (h *UserHandler) ListCredentials(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	u, err := h.userRepo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	creds, err := h.credRepo.ListByUser(r.Context(), u.ID, u.TenantID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if creds == nil {
		creds = []store.UserCredential{}
	}
	writeJSON(w, http.StatusOK, creds)
}

func (h *UserHandler) CreateCredential(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid uuid")
		return
	}
	u, err := h.userRepo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}

	var req createCredentialRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.ProviderType == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "providerType is required")
		return
	}

	cred := &store.UserCredential{
		UserID:       u.ID,
		TenantID:     u.TenantID,
		ProviderType: req.ProviderType,
	}

	if req.ProviderType == "password" {
		if req.Credential == "" {
			writeError(w, http.StatusBadRequest, "INVALID_INPUT", "credential (password) is required for password provider")
			return
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Credential), bcrypt.DefaultCost)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to hash password")
			return
		}
		cred.Credential = string(hash)
	}

	if req.Identifier != "" {
		cred.Identifier = &req.Identifier
	}

	if err := h.credRepo.Create(r.Context(), cred); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, cred)
}

func (h *UserHandler) DeleteCredential(w http.ResponseWriter, r *http.Request) {
	uid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid user uuid")
		return
	}
	u, err := h.userRepo.GetByUUID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
		return
	}
	credID, err := strconv.ParseInt(r.PathValue("credId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid credential id")
		return
	}
	if err := h.credRepo.SoftDeleteByUser(r.Context(), credID, u.ID); err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "credential not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
