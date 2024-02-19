package gateway

import (
	"api-gateway/pkg/config"
)

func newServerOptions() *config.ServerOptions {
	return &config.ServerOptions{
		Addr:    "127.0.0.1",
		Port:    "8080",
		Runmode: "debug",
	}
}

func checkServerOptionsValid(options *config.ServerOptions) *config.ServerOptions {
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
