package gateway

import (
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt"
	"crypto/rsa"
	"fmt"
)

func initRSA(cfg *config.JWTConfig) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pri, pub, err := jwt.InitRSAKeyPair(cfg.RSAPrivateKey, cfg.RSAPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("init RSA failed: %w", err)
	}
	return pri, pub, nil
}

func newServerOptions() *config.ServerOptions {
	return &config.ServerOptions{
		Addr:    "127.0.0.1",
		Port:    "8080",
		Runmode: "debug",
	}
}
