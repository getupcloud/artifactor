package scanner

import (
	"fmt"
	"strings"

	"github.com/anchore/go-logger"
	"github.com/anchore/grype/grype"

	"github.com/getupcloud/artifactor/internal/logx"
)

// grypeLogAdapter routes grype's library logging (go-logger) through logx so
// the DB download/update messages and their failures respect --log-level.
// grype's own default logger discards everything.
type grypeLogAdapter struct {
	fields []any
}

var _ logger.Logger = grypeLogAdapter{}

func (g grypeLogAdapter) Errorf(format string, args ...any) { logx.Errorf(g.prefix()+format, args...) }
func (g grypeLogAdapter) Error(args ...any)                 { logx.Errorf("%s%s", g.prefix(), fmt.Sprint(args...)) }
func (g grypeLogAdapter) Warnf(format string, args ...any)  { logx.Warnf(g.prefix()+format, args...) }
func (g grypeLogAdapter) Warn(args ...any)                  { logx.Warnf("%s%s", g.prefix(), fmt.Sprint(args...)) }
func (g grypeLogAdapter) Infof(format string, args ...any)  { logx.Infof(g.prefix()+format, args...) }
func (g grypeLogAdapter) Info(args ...any)                  { logx.Infof("%s%s", g.prefix(), fmt.Sprint(args...)) }
func (g grypeLogAdapter) Debugf(format string, args ...any) { logx.Debugf(g.prefix()+format, args...) }
func (g grypeLogAdapter) Debug(args ...any)                 { logx.Debugf("%s%s", g.prefix(), fmt.Sprint(args...)) }
func (g grypeLogAdapter) Tracef(format string, args ...any) { logx.Debugf(g.prefix()+format, args...) }
func (g grypeLogAdapter) Trace(args ...any)                 { logx.Debugf("%s%s", g.prefix(), fmt.Sprint(args...)) }

func (g grypeLogAdapter) WithFields(fields ...any) logger.MessageLogger {
	return grypeLogAdapter{fields: append(append([]any{}, g.fields...), fields...)}
}

func (g grypeLogAdapter) Nested(fields ...any) logger.Logger {
	return g.WithFields(fields...).(grypeLogAdapter)
}

// prefix renders the accumulated logrus-style key/value fields.
func (g grypeLogAdapter) prefix() string {
	if len(g.fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(g.fields)/2+1)
	for i := 0; i+1 < len(g.fields); i += 2 {
		parts = append(parts, fmt.Sprintf("%v=%v", g.fields[i], g.fields[i+1]))
	}
	if len(g.fields)%2 == 1 {
		parts = append(parts, fmt.Sprintf("%v", g.fields[len(g.fields)-1]))
	}
	return strings.Join(parts, " ") + ": "
}

// installGrypeLogger routes grype's internal logging through logx. It is
// idempotent and called whenever a DB curator is prepared.
func installGrypeLogger() {
	grype.SetLogger(grypeLogAdapter{})
}
