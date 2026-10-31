// Package logx is a tiny leveled logger built on the standard library log
// package. The global threshold is set once at startup from the
// --log-level flag; messages below the threshold are dropped.
//
// Every log line carries the source file of the caller — as a path relative
// to the repository root for files in this repo — and the line number:
//
//	artifactor: 2026/10/31 18:30:00 internal/scanner/scanner.go:123: message
package logx

import (
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"strings"
	"time"
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

// moduleRoot is the repository root, derived from this file's own path. It
// works for plain local builds (absolute path) and for -trimpath builds
// (path starting with the module path).
var moduleRoot = func() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	return strings.TrimSuffix(filepath.ToSlash(file), "/internal/logx/logx.go")
}()

func logf(l Level, prefix, format string, args ...any) {
	if l < current {
		return
	}
	file, line := callerSource(2) // logf <- Infof/etc <- caller
	header := log.Prefix() + time.Now().Format("2006/01/02 15:04:05")
	msg := fmt.Sprintf(prefix+format, args...)
	if file != "" {
		fmt.Fprintf(log.Writer(), "%s %s:%d: %s\n", header, file, line, msg)
	} else {
		fmt.Fprintf(log.Writer(), "%s %s\n", header, msg)
	}
}

// callerSource returns the file and line of the stack frame at the given
// depth relative to this function. Files inside the repository are shown
// relative to the repository root; files outside (e.g. the grype library)
// are shown with their last two path components.
func callerSource(depth int) (string, int) {
	_, file, line, ok := runtime.Caller(depth + 1) // +1: this function itself
	if !ok {
		return "", 0
	}
	file = filepath.ToSlash(file)
	if moduleRoot != "" && strings.HasPrefix(file, moduleRoot+"/") {
		return strings.TrimPrefix(file, moduleRoot+"/"), line
	}
	parts := strings.Split(file, "/")
	if len(parts) > 2 {
		file = strings.Join(parts[len(parts)-2:], "/")
	}
	return file, line
}
