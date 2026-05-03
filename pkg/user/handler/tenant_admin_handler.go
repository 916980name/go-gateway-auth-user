package handler

import (
	"net/http"

	userstore "api-gateway/pkg/user/store"
	rbacstore "api-gateway/pkg/rbac/store"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type TenantAdminHandler struct {
	userRepo   *userstore.UserRepo
	credRepo   *userstore.CredentialRepo
	tenantRepo *userstore.TenantRepo
	roleRepo   *rbacstore.RoleRepo
	db         *gorm.DB
	adminPath  string
}

func NewTenantAdminHandler(
	userRepo *userstore.UserRepo,
	credRepo *userstore.CredentialRepo,
	tenantRepo *userstore.TenantRepo,
	roleRepo *rbacstore.RoleRepo,
	db *gorm.DB,
	adminPath string,
) *TenantAdminHandler {
	return &TenantAdminHandler{
		userRepo:   userRepo,
		credRepo:   credRepo,
		tenantRepo: tenantRepo,
		roleRepo:   roleRepo,
		db:         db,
		adminPath:  adminPath,
	}
}

type createTenantAdminRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createTenantAdminResponse struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
}

func (h *TenantAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}

	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}

	var req createTenantAdminRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "username and password are required")
		return
	}

	err = h.db.WithContext(r.Context()).Transaction(func(tx *gorm.DB) error {
		// Create user
		u := &userstore.User{
			TenantID:    tenant.ID,
			Username:    req.Username,
			DisplayName: req.Username,
			Status:      1,
		}
		if err := tx.Create(u).Error; err != nil {
			return err
		}

		// Create password credential
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		cred := &userstore.UserCredential{
			UserID:       u.ID,
			TenantID:     tenant.ID,
			ProviderType: "password",
			Credential:   string(hash),
			Status:       1,
		}
		if err := tx.Create(cred).Error; err != nil {
			return err
		}

		// Ensure tenant_admin role exists in this tenant
		var taRole rbacstore.Role
		err = tx.Where("tenant_id = ? AND code = ?", tenant.ID, rbacstore.TenantAdminRoleCode).First(&taRole).Error
		if err != nil {
			taRole = rbacstore.Role{
				TenantID:    tenant.ID,
				Code:        rbacstore.TenantAdminRoleCode,
				Name:        rbacstore.TenantAdminRoleName,
				Description: "Tenant administrator",
			}
			if err := tx.Create(&taRole).Error; err != nil {
				return err
			}
		}

		// Assign tenant_admin role
		ur := rbacstore.UserRole{
			UserID:   u.ID,
			RoleID:   taRole.ID,
			TenantID: tenant.ID,
		}
		if err := tx.Create(&ur).Error; err != nil {
			return err
		}

		// Seed Casbin policies for this tenant
		if err := rbacstore.SeedTenantAdminPolicies(tx, tenant.Code, h.adminPath); err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}

	resp := createTenantAdminResponse{
		Username: req.Username,
	}
	writeJSON(w, http.StatusCreated, resp)
}
