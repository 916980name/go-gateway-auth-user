package log

import (
	"api-gateway/pkg/common"
	"context"
	"sync"
	"time"

	"github.com/go-chi/chi/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ZapLogger struct {
	logger *zap.Logger
}

type Logger interface {
	Debugw(msg string, keysAndValues ...interface{})
	Infow(msg string, keysAndValues ...interface{})
	Warnw(msg string, keysAndValues ...interface{})
	Errorw(msg string, keysAndValues ...interface{})
	Panicw(msg string, keysAndValues ...interface{})
	Fatalw(msg string, keysAndValues ...interface{})
	Sync()
}

var _ Logger = &ZapLogger{}

var (
	mu sync.Mutex

	std = NewLogger(NewOptions())
)

func NewLogger(opts *Options) *ZapLogger {
	if opts == nil {
		opts = NewOptions()
	}

	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(opts.Level)); err != nil {
		zapLevel = zapcore.InfoLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.MessageKey = "message"
	encoderConfig.TimeKey = "timestamp"
	encoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
	}
	encoderConfig.EncodeDuration = func(d time.Duration, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendFloat64(float64(d) / float64(time.Millisecond))
	}

	cfg := &zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Encoding:         opts.Format,
		EncoderConfig:    encoderConfig,
		OutputPaths:      opts.OutputPaths,
		ErrorOutputPaths: []string{"stderr"},
	}

	z, err := cfg.Build(zap.AddStacktrace(zapcore.PanicLevel), zap.AddCallerSkip(1))
	if err != nil {
		panic(err)
	}
	logger := &ZapLogger{logger: z}

	zap.RedirectStdLog(z)
	return logger
}

func Init(opts *Options) {
	mu.Lock()
	defer mu.Unlock()
	opts = checkOptionValid(opts)
	std = NewLogger(opts)
}

func checkOptionValid(opts *Options) *Options {
	validOpt := NewOptions()
	if opts.Level != "" {
		validOpt.Level = opts.Level
	}
	if opts.Format != "" {
		validOpt.Format = opts.Format
	}
	if opts.OutputPaths != nil && len(opts.OutputPaths) > 0 {
		validOpt.OutputPaths = opts.OutputPaths
	}
	return validOpt
}

func Sync() { std.Sync() }

func (l *ZapLogger) Sync() {
	_ = l.logger.Sync()
}

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

func C(ctx context.Context) *ZapLogger {
	return std.C(ctx)
}

func (l *ZapLogger) clone() *ZapLogger {
	lc := *l
	return &lc
}

func (l *ZapLogger) C(ctx context.Context) *ZapLogger {
	lc := l.clone()

	if requestID := ctx.Value(common.HEADER_REQUEST_ID); requestID != nil {
		lc.logger = lc.logger.With(zap.Any(common.HEADER_REQUEST_ID, requestID))
	}

	return lc
}

func G(ctx context.Context) *ZapLogger {
	return std.G(ctx)
}

func (l *ZapLogger) G(ctx context.Context) *ZapLogger {
	lc := l.clone()

	if requestID := ctx.Value(middleware.RequestIDKey); requestID != nil {
		lc.logger = lc.logger.With(zap.Any(common.HEADER_REQUEST_ID, requestID))
	}

	return lc
}
