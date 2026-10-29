package logx

import "testing"

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
