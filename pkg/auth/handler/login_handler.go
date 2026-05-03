package handler

import (
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"api-gateway/pkg/auth"
	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
)

const (
	headerAccessToken  = "Authorization"
	headerRefreshToken = "Refresh"

	tokenDefaultTimeout        = 24 * time.Hour
	refreshTokenDefaultTimeout = 120 * time.Hour
)

type LoginHandlerConfig struct {
	PrivateKey    *rsa.PrivateKey
	OnlineCache   *cache.CacheOper
	CookieEnabled bool
	HasRefresh    bool
}

type LoginHandler struct {
	auth *auth.Module
	cfg  LoginHandlerConfig
}

func NewLoginHandler(authMod *auth.Module, cfg LoginHandlerConfig) *LoginHandler {
	return &LoginHandler{auth: authMod, cfg: cfg}
}

type loginRequest struct {
	Provider   string `json:"provider"`
	Identifier string `json:"identifier"`
	Credential string `json:"credential"`
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "invalid request body")
		return
	}
	defer r.Body.Close()

	if req.Provider == "" || req.Identifier == "" || req.Credential == "" {
		writeError(w, http.StatusBadRequest, "INVALID_INPUT", "provider, identifier, and credential are required")
		return
	}

	userMod := h.auth.UserModule()
	hostname := r.Host
	tenantInfo, ok := userMod.ResolveTenant(hostname)
	if !ok || tenantInfo == nil {
		writeError(w, http.StatusBadRequest, "UNKNOWN_DOMAIN", "domain not recognized")
		return
	}

	tenant, err := userMod.TenantRepo().GetByCode(r.Context(), tenantInfo.Code)
	if err != nil {
		slog.Error("login: tenant lookup failed", "error", err, "tenantCode", tenantInfo.Code)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}

	result, err := h.auth.Authenticate(r.Context(), auth.AuthRequest{
		TenantID:   tenant.ID,
		Provider:   req.Provider,
		Identifier: req.Identifier,
		Credential: req.Credential,
	})
	if err != nil {
		if err == auth.ErrInvalidCredentials || err == auth.ErrCredentialDisabled || err == auth.ErrUserDisabled {
			writeError(w, http.StatusUnauthorized, "AUTH_FAILED", "invalid credentials")
			return
		}
		if err == auth.ErrProviderNotFound {
			writeError(w, http.StatusBadRequest, "UNSUPPORTED_PROVIDER", "provider not supported")
			return
		}
		slog.Error("login: authentication error", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}

	payload := map[string]interface{}{
		"username":    result.Username,
		"idKey":       result.Username,
		"tenant_uuid": tenantInfo.UUID,
	}

	token, err := jwt.GenerateJWTRSA(payload, tokenDefaultTimeout, h.cfg.PrivateKey)
	if err != nil {
		slog.Error("login: token generation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		return
	}

	if h.cfg.OnlineCache != nil {
		hashStr := common.StringToHashBase64(token)
		(*h.cfg.OnlineCache).Set(r.Context(), onlineCacheKey(hostname, result.Username), hashStr)
	}

	w.Header().Set(headerAccessToken, token)

	if h.cfg.HasRefresh {
		refreshToken, err := jwt.GenerateJWTRSA(payload, refreshTokenDefaultTimeout, h.cfg.PrivateKey)
		if err != nil {
			slog.Error("login: refresh token generation failed", "error", err)
		} else {
			w.Header().Set(headerRefreshToken, refreshToken)
		}
	}

	if h.cfg.CookieEnabled {
		expires := time.Now().Add(tokenDefaultTimeout)
		http.SetCookie(w, &http.Cookie{
			Name:     headerAccessToken,
			Value:    token,
			Path:     "/",
			Expires:  expires,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "login successful"})
}

func onlineCacheKey(hostname, username string) string {
	return "online:" + hostname + ":" + username
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
