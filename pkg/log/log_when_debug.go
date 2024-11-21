//go:build debug
// +build debug

package log

import (
	"api-gateway/pkg/common"

	"go.uber.org/zap"
)

func Debugw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Debugw(msg, keysAndValues...)
}

func (l *ZapLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Debugw(msg, keysAndValues...)
}

func Infow(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Infow(msg, keysAndValues...)
}

func (l *ZapLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Infow(msg, keysAndValues...)
}

func Warnw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Warnw(msg, keysAndValues...)
}

func (l *ZapLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Warnw(msg, keysAndValues...)
}

func Errorw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Errorw(msg, keysAndValues...)
}

func (l *ZapLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Errorw(msg, keysAndValues...)
}

func Panicw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Panicw(msg, keysAndValues...)
}

func (l *ZapLogger) Panicw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Panicw(msg, keysAndValues...)
}

func Fatalw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Fatalw(msg, keysAndValues...)
}

func (l *ZapLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().With(zap.Int(TAG_GO_ROUTINE_ID, common.GetGoroutineID())).Fatalw(msg, keysAndValues...)
}
