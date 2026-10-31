package logx

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := map[string]Level{
		"debug":   LevelDebug,
		"DEBUG":   LevelDebug,
		"info":    LevelInfo,
		"warn":    LevelWarn,
		"warning": LevelWarn,
		"err":     LevelErr,
		"error":   LevelErr,
		" Err ":   LevelErr,
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("Parse(%q) = %v, want %v", in, got, want)
		}
	}
	for _, in := range []string{"", "verbose", "trace", "3"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) returned no error", in)
		}
	}
}

func TestCallerSource(t *testing.T) {
	file, line := callerSource(0) // this test function (immediate caller)
	if file != "internal/logx/logx_test.go" {
		t.Fatalf("callerSource file = %q, want internal/logx/logx_test.go", file)
	}
	if line <= 0 {
		t.Fatalf("callerSource line = %d", line)
	}
}

func TestLogfCarriesCallerFileAndLine(t *testing.T) {
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(oldWriter)

	prev := current
	current = LevelDebug
	defer func() { current = prev }()

	Infof("hello %d", 42)
	got := buf.String()
	if !strings.Contains(got, "internal/logx/logx_test.go:") {
		t.Fatalf("log line missing caller file:line: %q", got)
	}
	if !strings.Contains(got, ": hello 42\n") {
		t.Fatalf("log line missing message: %q", got)
	}
}
