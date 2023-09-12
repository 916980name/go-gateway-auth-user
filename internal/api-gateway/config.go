package gateway

import (
	"github.com/spf13/viper"
)

type ServerOptions struct {
	Addr    string
	Runmode string
	Port    string
}

func newServerOptions() *ServerOptions {
	return &ServerOptions{
		Addr:    "127.0.0.1",
		Port:    "8080",
		Runmode: "debug",
	}
}

func serverOptions() *ServerOptions {
	return &ServerOptions{
		Addr:    viper.GetString("server.addr"),
		Runmode: viper.GetString("server.runmode"),
		Port:    viper.GetString("server.port"),
	}
}

func checkServerOptionsValid(options *ServerOptions) *ServerOptions {
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
