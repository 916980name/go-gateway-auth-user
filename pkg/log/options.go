package log

import (
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
)

type Options struct {
	Level       string
	Format      string
	OutputPaths []string
}

func NewOptions() *Options {
	return &Options{
		Level:       zapcore.InfoLevel.String(),
		Format:      "console",
		OutputPaths: []string{"stdout"},
	}
}

func ReadLogOptions() *Options {
	return &Options{
		Level:       viper.GetString("log.level"),
		Format:      viper.GetString("log.format"),
		OutputPaths: viper.GetStringSlice("log.output-paths"),
	}
}
