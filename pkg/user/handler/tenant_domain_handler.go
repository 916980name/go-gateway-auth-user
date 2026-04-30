package handler

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"api-gateway/pkg/user/store"

	"github.com/google/uuid"
)

type TenantDomainHandler struct {
	domainRepo *store.TenantDomainRepo
	tenantRepo *store.TenantRepo
	onChange   func()
}

func NewTenantDomainHandler(domainRepo *store.TenantDomainRepo, tenantRepo *store.TenantRepo, onChange func()) *TenantDomainHandler {
	return &TenantDomainHandler{domainRepo: domainRepo, tenantRepo: tenantRepo, onChange: onChange}
}

var domainPattern = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

type createDomainRequest struct {
	Pattern string `json:"pattern"`
}

func (h *TenantDomainHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}
	domains, err := h.domainRepo.ListByTenant(r.Context(), tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if domains == nil {
		domains = []store.TenantDomain{}
	}
	writeJSON(w, http.StatusOK, domains)
}

func (h *TenantDomainHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantUUID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid tenant uuid")
		return
	}
	var req createDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	req.Pattern = strings.ToLower(strings.TrimSpace(req.Pattern))
	if !domainPattern.MatchString(req.Pattern) {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid domain pattern: must be exact domain or *.domain.tld")
		return
	}

	tenant, err := h.tenantRepo.GetByUUID(r.Context(), tenantUUID)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "tenant not found")
		return
	}

	if err := h.domainRepo.CheckOverlap(r.Context(), tenant.ID, req.Pattern); err != nil {
		writeError(w, http.StatusConflict, "DOMAIN_OVERLAP", err.Error())
		return
	}

	d := &store.TenantDomain{TenantID: tenant.ID, Pattern: req.Pattern}
	if err := h.domainRepo.Create(r.Context(), d); err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "DOMAIN_EXISTS", "domain pattern already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	writeJSON(w, http.StatusCreated, d)
}

func (h *TenantDomainHandler) Delete(w http.ResponseWriter, r *http.Request) {
	domainID, err := strconv.ParseInt(r.PathValue("domainId"), 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid domain id")
		return
	}
	if err := h.domainRepo.Delete(r.Context(), domainID); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	if h.onChange != nil {
		h.onChange()
	}
	w.WriteHeader(http.StatusNoContent)
}
