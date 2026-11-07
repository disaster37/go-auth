// Package observ provides structured logging adapters used across the go-auth
// packages. It is a documented cross-cutting exception to the pure-domain
// dependency rule: service and handler layers may inject a Logger.
package observ

import (
	"fmt"
	"log"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"
)

// Logger is the structured logging interface used by the library.
// Implementations must be safe for concurrent use.
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, err error, fields map[string]any)
}

// LogrusAdapter adapts a logrus.Logger to Logger.
type LogrusAdapter struct {
	logger *logrus.Logger
}

// NewLogrusAdapter returns a Logger backed by l. A nil logger yields a no-op
// logger.
func NewLogrusAdapter(l *logrus.Logger) Logger {
	if l == nil {
		return NewNoopLogger()
	}
	return &LogrusAdapter{logger: l}
}

func (a *LogrusAdapter) Debug(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (a *LogrusAdapter) Info(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Info(msg)
}

func (a *LogrusAdapter) Warn(msg string, fields map[string]any) {
	a.logger.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (a *LogrusAdapter) Error(msg string, err error, fields map[string]any) {
	entry := a.logger.WithFields(logrus.Fields(fields))
	if err != nil {
		entry = entry.WithError(err)
	}
	entry.Error(msg)
}

// StdlibAdapter adapts a standard library *log.Logger to Logger.
type StdlibAdapter struct {
	logger *log.Logger
}

// NewStdlibAdapter returns a Logger backed by l. A nil logger yields a no-op
// logger.
func NewStdlibAdapter(l *log.Logger) Logger {
	if l == nil {
		return NewNoopLogger()
	}
	return &StdlibAdapter{logger: l}
}

func (a *StdlibAdapter) Debug(msg string, fields map[string]any) {
	a.log("DEBUG", msg, nil, fields)
}

func (a *StdlibAdapter) Info(msg string, fields map[string]any) {
	a.log("INFO", msg, nil, fields)
}

func (a *StdlibAdapter) Warn(msg string, fields map[string]any) {
	a.log("WARN", msg, nil, fields)
}

func (a *StdlibAdapter) Error(msg string, err error, fields map[string]any) {
	a.log("ERROR", msg, err, fields)
}

func (a *StdlibAdapter) log(level, msg string, err error, fields map[string]any) {
	parts := make([]string, 0, len(fields)+2)
	parts = append(parts, fmt.Sprintf("level=%s", level))
	if err != nil {
		parts = append(parts, fmt.Sprintf("error=%v", err))
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, fields[key]))
	}
	a.logger.Printf("%s %s", msg, strings.Join(parts, " "))
}

// NoopLogger discards every log entry.
type NoopLogger struct{}

// NewNoopLogger returns a Logger that discards all output.
func NewNoopLogger() Logger { return NoopLogger{} }

func (NoopLogger) Debug(string, map[string]any)        {}
func (NoopLogger) Info(string, map[string]any)         {}
func (NoopLogger) Warn(string, map[string]any)         {}
func (NoopLogger) Error(string, error, map[string]any) {}
