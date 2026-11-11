package observ

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNoopLogger(t *testing.T) {
	l := NewNoopLogger()
	l.Debug("d", nil)
	l.Info("i", nil)
	l.Warn("w", nil)
	l.Error("e", errors.New("x"), nil)
}

func TestStdlibAdapter(t *testing.T) {
	var buf bytes.Buffer
	l := NewStdlibAdapter(log.New(&buf, "", 0))
	l.Debug("debug msg", map[string]any{"b": 2, "a": 1})
	l.Info("info msg", nil)
	l.Warn("warn msg", nil)
	l.Error("error msg", errors.New("boom"), map[string]any{"k": "v"})
	out := buf.String()
	for _, want := range []string{"debug msg", "level=DEBUG", "a=1", "b=2", "info msg", "warn msg", "error msg", "error=boom", "k=v"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestStdlibAdapterNil(t *testing.T) {
	if _, ok := NewStdlibAdapter(nil).(NoopLogger); !ok {
		t.Fatal("nil stdlib logger must yield NoopLogger")
	}
}

func TestLogrusAdapter(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetLevel(logrus.DebugLevel)
	l := NewLogrusAdapter(logger)
	l.Debug("d", map[string]any{"x": 1})
	l.Info("i", nil)
	l.Warn("w", nil)
	l.Error("e", errors.New("boom"), map[string]any{"y": 2})
	out := buf.String()
	for _, want := range []string{"d", "i", "w", "e", "boom", "x=1", "y=2"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
}

func TestLogrusAdapterNil(t *testing.T) {
	if _, ok := NewLogrusAdapter(nil).(NoopLogger); !ok {
		t.Fatal("nil logrus logger must yield NoopLogger")
	}
}
