package handler

import (
	"crypto/rsa"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"api-gateway/pkg/cache"
	"api-gateway/pkg/common"
	"api-gateway/pkg/jwt"
)

type LogoutHandlerConfig struct {
	PublicKey     *rsa.PublicKey
	OnlineCache  *cache.CacheOper
	CookieEnabled bool
}

type LogoutHandler struct {
	cfg LogoutHandlerConfig
}

func NewLogoutHandler(cfg LogoutHandlerConfig) *LogoutHandler {
	return &LogoutHandler{cfg: cfg}
}

func (h *LogoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "POST required")
		return
	}

	hostname := r.Host

	tokenStr := extractToken(r)
	if tokenStr == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing token")
		return
	}

	dat, err := jwt.VerifyJWTRSA(tokenStr, h.cfg.PublicKey)
	if err != nil {
		slog.Debug("logout: token verification failed", "error", err)
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token")
		return
	}

	datMap, ok := dat.(map[string]interface{})
	if !ok {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token payload")
		return
	}

	username, _ := datMap["username"].(string)
	if username == "" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid token payload")
		return
	}

	if h.cfg.OnlineCache != nil {
		key := onlineCacheKey(hostname, username)
		cached, err := (*h.cfg.OnlineCache).Get(r.Context(), key)
		if err == nil && cached == common.StringToHashBase64(tokenStr) {
			(*h.cfg.OnlineCache).Remove(r.Context(), key)
		}
	}

	if h.cfg.CookieEnabled {
		expired := time.Unix(0, 0)
		http.SetCookie(w, &http.Cookie{
			Name:     headerAccessToken,
			Value:    "",
			Path:     "/",
			Expires:  expired,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     headerRefreshToken,
			Value:    "",
			Path:     "/",
			Expires:  expired,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "logout successful"})
}

func extractToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Bearer ") {
			return strings.TrimPrefix(auth, "Bearer ")
		}
		return auth
	}
	if cookie, err := r.Cookie(headerAccessToken); err == nil {
		return cookie.Value
	}
	return ""
}
