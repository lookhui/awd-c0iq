package logger

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"awd-h1m-pro/internal/util"
)

type EventEmitter func(name string, data any)

type PrettyHandler struct {
	handler slog.Handler
}

type Extend struct {
	Logger *slog.Logger
}

var (
	mu          sync.RWMutex
	logFile     *os.File
	baseLogger  = slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelInfo}))
	eventSender EventEmitter
)

func NewPrettyHandler(w io.Writer) *PrettyHandler {
	return &PrettyHandler{
		handler: slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}),
	}
}

func (h *PrettyHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *PrettyHandler) Handle(ctx context.Context, record slog.Record) error {
	return h.handler.Handle(ctx, record)
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &PrettyHandler{handler: h.handler.WithAttrs(attrs)}
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	return &PrettyHandler{handler: h.handler.WithGroup(name)}
}

func (e *Extend) Error(err error) {
	if err != nil {
		Error("error", "error", err.Error())
	}
}

func Init(emitter EventEmitter, ctx context.Context) error {
	_ = ctx
	return InitLogger(emitter)
}

func InitLogger(emitter EventEmitter) error {
	mu.Lock()
	defer mu.Unlock()
	eventSender = emitter
	if err := util.EnsureDir(util.LogDir()); err != nil {
		return err
	}
	logPath := filepath.Join(util.LogDir(), fmt.Sprintf("awd-c0iq-%s.log", time.Now().Format("2006-01-02")))
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if logFile != nil {
		_ = logFile.Close()
	}
	logFile = file
	handler := slog.NewJSONHandler(io.MultiWriter(os.Stdout, file), &slog.HandlerOptions{Level: slog.LevelInfo})
	baseLogger = slog.New(handler)
	return nil
}

func Info(message string, args ...any) {
	logWithLevel(slog.LevelInfo, message, args...)
}

func Success(message string, args ...any) {
	logWithLevel(slog.LevelInfo, message, append([]any{"success", true}, args...)...)
}

func Warning(message string, args ...any) {
	logWithLevel(slog.LevelWarn, message, args...)
}

func Error(message string, args ...any) {
	logWithLevel(slog.LevelError, message, args...)
}

func logWithLevel(level slog.Level, message string, args ...any) {
	mu.RLock()
	logger := baseLogger
	emitter := eventSender
	mu.RUnlock()
	logger.Log(context.Background(), level, message, args...)
	if emitter != nil {
		fields := extractFields(args...)
		emitter("log", map[string]any{
			"level":   level.String(),
			"message": message,
			"fields":  fields,
			"time":    time.Now().Format(time.RFC3339),
		})
	}
}

func extractFields(args ...any) map[string]any {
	result := make(map[string]any)
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		result[key] = args[i+1]
	}
	return result
}

func formatLevel(level slog.Level) string {
	return level.String()
}

func applyLevelColor(level slog.Level, message string) string {
	_ = level
	return message
}

func extractAndFormatFields(args ...any) string {
	return formatFields(extractFields(args...))
}

func formatFields(fields map[string]any) string {
	if len(fields) == 0 {
		return ""
	}
	out, _ := json.Marshal(fields)
	return string(out)
}

func formatFieldsAsJSON(fields map[string]any) string {
	return formatFields(fields)
}

func outputLog(level slog.Level, message string, args ...any) {
	logWithLevel(level, message, args...)
}
