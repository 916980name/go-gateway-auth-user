package gateway

import (
	"api-gateway/pkg/config"
	"api-gateway/pkg/jwt"
	"api-gateway/pkg/log"
	"crypto/rsa"
)

var (
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
)

func initRSA(cfg *config.JWTConfig) {
	pri, pub, err := jwt.InitRSAKeyPair(cfg.RSAPrivateKey, cfg.RSAPublicKey)
	if err != nil {
		log.Errorw("init RSA failed", "error", err.Error())
		return
	}
	rsaPrivateKey = pri
	rsaPublicKey = pub
}

func newServerOptions() *config.ServerOptions {
	return &config.ServerOptions{
		Addr:    "127.0.0.1",
		Port:    "8080",
		Runmode: "debug",
	}
}

func makeServerOptionsValid(options *config.ServerOptions) *config.ServerOptions {
	opts := newServerOptions()
	if options == nil {
		return opts
	}
	if options.Addr != "" {
		opts.Addr = options.Addr
	}
	if options.Port != "" {
		opts.Port = options.Port
	}
	if options.Runmode != "" {
		opts.Runmode = options.Runmode
	}
	return opts
}
