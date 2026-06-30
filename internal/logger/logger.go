// Package logger provides structured JSON logging for Fortress V6.
//
// Usage:
//
//	logger.Info("pipeline started", "mode", "defend", "workers", 6)
//	logger.Warn("high memory usage", "pct", 87.5, "pid", os.Getpid())
//	logger.Error("failed to bind", "port", 9700, "err", err)
//	logger.Debug("packet received", "src", ip, "bytes", n)
//
// Output: one JSON object per line to stdout (plus optional file sink).
// No external dependencies — pure standard library.
package logger

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level controls which messages are emitted.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelSilent
)

var levelNames = map[Level]string{
	LevelDebug: "DEBUG",
	LevelInfo:  "INFO",
	LevelWarn:  "WARN",
	LevelError: "ERROR",
}

// Fields is a key-value map for structured logging.
type Fields map[string]interface{}

// Logger is a structured JSON logger.
type Logger struct {
	mu       sync.Mutex
	level    Level
	stdout   io.Writer
	file     io.WriteCloser
	service  string
}

// entry is the JSON log structure.
type entry struct {
	Time    string      `json:"time"`
	Level   string      `json:"level"`
	Service string      `json:"service"`
	Msg     string      `json:"msg"`
	Fields  Fields      `json:"fields,omitempty"`
}

// New creates a logger with the given service name and minimum level.
// Call Close() when done to flush the file sink.
func New(service string, level Level, logDir string) *Logger {
	l := &Logger{
		level:   level,
		stdout:  os.Stdout,
		service: service,
	}

	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err == nil {
			path := filepath.Join(logDir, "fortress.log")
			f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err == nil {
				l.file = f
			}
		}
	}

	return l
}

// Close flushes and closes the file sink.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// SetLevel changes the minimum log level at runtime.
func (l *Logger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Level returns the current minimum log level.
func (l *Logger) Level() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Debug logs a structured debug message.
func (l *Logger) Debug(msg string, fields ...interface{}) {
	l.log(LevelDebug, msg, fields...)
}

// Info logs a structured info message.
func (l *Logger) Info(msg string, fields ...interface{}) {
	l.log(LevelInfo, msg, fields...)
}

// Warn logs a structured warning message.
func (l *Logger) Warn(msg string, fields ...interface{}) {
	l.log(LevelWarn, msg, fields...)
}

// Error logs a structured error message.
func (l *Logger) Error(msg string, fields ...interface{}) {
	l.log(LevelError, msg, fields...)
}

func (l *Logger) log(level Level, msg string, fields ...interface{}) {
	l.mu.Lock()
	currentLevel := l.level
	l.mu.Unlock()

	if level < currentLevel {
		return
	}

	e := entry{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Level:   levelNames[level],
		Service: l.service,
		Msg:     msg,
	}

	if len(fields) > 0 {
		f := make(Fields)
		for i := 0; i+1 < len(fields); i += 2 {
			key, ok := fields[i].(string)
			if ok {
				f[key] = fields[i+1]
			}
		}
		e.Fields = f
	}

	data, _ := json.Marshal(e)

	l.mu.Lock()
	l.stdout.Write(data)
	fmt.Fprintln(l.stdout)
	if l.file != nil {
		l.file.Write(data)
		fmt.Fprintln(l.file)
	}
	l.mu.Unlock()
}

// ───────────────────────────────────────────────────────────────────────────
// Package-level default logger (convenience for quick adoption)
// ───────────────────────────────────────────────────────────────────────────

var defaultLogger *Logger
var defaultMu sync.Mutex

func init() {
	defaultLogger = New("fortress", LevelInfo, "")
}

// Init initializes the package-level logger. Call once at startup.
func Init(service string, level Level, logDir string) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultLogger != nil {
		defaultLogger.Close()
	}
	defaultLogger = New(service, level, logDir)
}

// Debug logs at DEBUG level via the default logger.
func Debug(msg string, fields ...interface{}) {
	defaultMu.Lock()
	if defaultLogger != nil {
		defaultLogger.log(LevelDebug, msg, fields...)
	}
	defaultMu.Unlock()
}

// Info logs at INFO level via the default logger.
func Info(msg string, fields ...interface{}) {
	defaultMu.Lock()
	if defaultLogger != nil {
		defaultLogger.log(LevelInfo, msg, fields...)
	}
	defaultMu.Unlock()
}

// Warn logs at WARN level via the default logger.
func Warn(msg string, fields ...interface{}) {
	defaultMu.Lock()
	if defaultLogger != nil {
		defaultLogger.log(LevelWarn, msg, fields...)
	}
	defaultMu.Unlock()
}

// Error logs at ERROR level via the default logger.
func Error(msg string, fields ...interface{}) {
	defaultMu.Lock()
	if defaultLogger != nil {
		defaultLogger.log(LevelError, msg, fields...)
	}
	defaultMu.Unlock()
}

// Shutdown flushes the default logger. Call at process exit.
func Shutdown() {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if defaultLogger != nil {
		defaultLogger.Close()
	}
}

// ParseLevel converts a string to Level. Accepts: debug, info, warn, error, silent.
func ParseLevel(s string) Level {
	switch s {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn":
		return LevelWarn
	case "error":
		return LevelError
	case "silent":
		return LevelSilent
	default:
		return LevelInfo
	}
}

// PrintfBridge wraps a *log.Logger to redirect standard library log.Printf
// output through the structured logger. Install with:
//
//	log.SetFlags(0)
//	log.SetOutput(logger.PrintfBridge(LevelInfo))
type PrintfBridge struct {
	level Level
}

func (p PrintfBridge) Write(data []byte) (int, error) {
	msg := string(data)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	switch p.level {
	case LevelDebug:
		Debug(msg)
	case LevelInfo:
		Info(msg)
	case LevelWarn:
		Warn(msg)
	case LevelError:
		Error(msg)
	}
	return len(data), nil
}
