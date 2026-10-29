package scanner

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/getupcloud/artifactor/internal/logx"
)

func TestGrypeLogAdapter(t *testing.T) {
	var buf bytes.Buffer
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(oldFlags)
		logx.Set(logx.LevelInfo)
	})

	g := grypeLogAdapter{}

	// info passes at the default level
	g.Infof("downloading %s", "db")
	if !strings.Contains(buf.String(), "downloading db") {
		t.Errorf("info not forwarded: %q", buf.String())
	}

	// logrus-style fields render as key=value pairs
	g.WithFields("url", "https://x", "time", "1s").Warnf("slow")
	if !strings.Contains(buf.String(), "WARNING: url=https://x time=1s: slow") {
		t.Errorf("fields not rendered: %q", buf.String())
	}

	// debug and trace are dropped at the default level
	buf.Reset()
	g.Debugf("hidden debug")
	g.Tracef("hidden trace")
	if buf.Len() != 0 {
		t.Errorf("debug/trace leaked at info level: %q", buf.String())
	}

	// errors always pass
	buf.Reset()
	g.Errorf("boom %d", 1)
	if !strings.Contains(buf.String(), "ERROR: boom 1") {
		t.Errorf("error not forwarded: %q", buf.String())
	}
}
