// Package logx is a tiny leveled logger built on the standard library log
// package. The global threshold is set once at startup from the
// --log-level flag; messages below the threshold are dropped.
package logx

import (
	"fmt"
	"log"
	"strings"
)

// Level is a verbosity threshold.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelErr
)

var current = LevelInfo

// Set replaces the global threshold.
func Set(l Level) { current = l }

// Parse maps a level name ("debug", "info", "warn" or "err") to a Level.
func Parse(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "err", "error":
		return LevelErr, nil
	}
	return LevelInfo, fmt.Errorf("invalid log level %q (want debug, info, warn or err)", s)
}

// Debugf logs extra-verbose detail, shown only with --log-level debug.
func Debugf(format string, args ...any) { logf(LevelDebug, "DEBUG: ", format, args...) }

// Infof logs normal progress messages (the default threshold).
func Infof(format string, args ...any) { logf(LevelInfo, "", format, args...) }

// Warnf logs recoverable problems.
func Warnf(format string, args ...any) { logf(LevelWarn, "WARNING: ", format, args...) }

// Errorf logs errors that do not stop the process.
func Errorf(format string, args ...any) { logf(LevelErr, "ERROR: ", format, args...) }

func logf(l Level, prefix, format string, args ...any) {
	if l < current {
		return
	}
	log.Printf(prefix+format, args...)
}
