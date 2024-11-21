//go:build !debug
// +build !debug

package log

func Debugw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Debugw(msg, keysAndValues...)
}

func (l *ZapLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Debugw(msg, keysAndValues...)
}

func Infow(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Infow(msg, keysAndValues...)
}

func (l *ZapLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Infow(msg, keysAndValues...)
}

func Warnw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Warnw(msg, keysAndValues...)
}

func (l *ZapLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Warnw(msg, keysAndValues...)
}

func Errorw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Errorw(msg, keysAndValues...)
}

func (l *ZapLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Errorw(msg, keysAndValues...)
}

func Panicw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Panicw(msg, keysAndValues...)
}

func (l *ZapLogger) Panicw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Panicw(msg, keysAndValues...)
}

func Fatalw(msg string, keysAndValues ...interface{}) {
	std.logger.Sugar().Fatalw(msg, keysAndValues...)
}

func (l *ZapLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.logger.Sugar().Fatalw(msg, keysAndValues...)
}
