// Package metrics exposes the scan store as Prometheus metrics in the text
// exposition format, served on a dedicated HTTP endpoint (GET /metrics) with
// a listen address separate from the SPA server (--metrics-listen, defaults
// 0.0.0.0:9090). The exposition is rendered from the store on every scrape
// with no external dependency.
package metrics

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/scanner"
)

// Default listen parts of --metrics-listen: every interface, port 9090.
const (
	DefaultIP   = "0.0.0.0"
	DefaultPort = "9090"
)

// ParseListen normalizes a --metrics-listen value into a listen address of
// the form "[ip]:port". The IP and the port are both optional (defaults
// DefaultIP and DefaultPort): accepted forms are "ip:port", ":port", "port",
// "ip", "[ipv6]:port", "[ipv6]" and a bare IPv6 address. An invalid port
// (not numeric or outside 0-65535) returns an error.
func ParseListen(s string) (string, error) {
	s = strings.TrimSpace(s)
	host, port := DefaultIP, DefaultPort
	switch {
	case s == "":
		// both defaults
	case strings.HasPrefix(s, "["):
		// bracketed IPv6: [::1] or [::1]:9091
		end := strings.Index(s, "]")
		if end < 0 {
			return "", fmt.Errorf("invalid listen address %q (missing closing bracket)", s)
		}
		host = s[1:end]
		if rest := s[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return "", fmt.Errorf("invalid listen address %q (unexpected text after %q)", s, s[:end+1])
			}
			port = rest[1:]
		}
	default:
		switch strings.Count(s, ":") {
		case 0:
			// no colon: a bare port (all digits) or an IP/hostname alone
			if isDigits(s) {
				port = s
			} else {
				host = s
			}
		case 1:
			// "ip:port" or ":port" (host may be empty)
			var err error
			host, port, err = net.SplitHostPort(s)
			if err != nil {
				return "", fmt.Errorf("invalid listen address %q: %v", s, err)
			}
		default:
			// bare IPv6 address (a port would need brackets)
			host = s
		}
	}
	if host == "" {
		host = DefaultIP
	}
	if port == "" {
		port = DefaultPort
	}
	if !validPort(port) {
		return "", fmt.Errorf("invalid metrics port %q (must be a number between 0 and 65535)", port)
	}
	return net.JoinHostPort(host, port), nil
}

// isDigits reports whether s is non-empty and composed only of digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// validPort reports whether p is a numeric port in the range 0-65535.
func validPort(p string) bool {
	n, err := strconv.Atoi(p)
	return err == nil && n >= 0 && n <= 65535
}

// splitImageRef splits a container image reference into the repository URL
// (without tag and digest) and the tag. A digest suffix (@sha256:...) is
// dropped; the tag is the part after the last ":" following the last "/",
// so a ":" inside a registry port (registry:5000/...) is not taken as the
// tag separator.
func splitImageRef(ref string) (name, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	name = ref
	slash := strings.LastIndex(ref, "/")
	if j := strings.LastIndex(ref[slash+1:], ":"); j >= 0 {
		j += slash + 1
		name = ref[:j]
		tag = ref[j+1:]
	}
	return name, tag
}

// Handler serves the Prometheus metrics of the scan store.
type Handler struct {
	store *scanner.Store
}

// New returns a metrics handler that renders the current state of the store
// on every scrape (no cache: the exposition always reflects the store as it
// is at request time).
func New(store *scanner.Store) *Handler {
	return &Handler{store: store}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/metrics" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(h.render())
}

// label is one Prometheus label of a sample.
type label struct {
	name  string
	value string
}

// render builds the full text exposition of the store: one
// artifactor_image_status series per known image per workload instance and
// one artifactor_image_cve series per deduplicated CVE of scanned images per
// workload instance, all carrying image (repository URL without tag), tag,
// namespace, kind and object (the workload running the image; empty when
// the image is not attached to a cluster object, e.g. --from-sbom) and
// last_scan (the image's last successful scan time, RFC3339 UTC, empty
// when never scanned) as labels. Series are sorted for a deterministic
// output.
func (h *Handler) render() []byte {
	var statusLines, cveLines []string
	for _, res := range h.store.Snapshot("") {
		name, tag := splitImageRef(res.Image)
		cves := dedupeCVEs(res.Cves)
		lastScan := ""
		if res.ScannedAt != nil {
			lastScan = res.ScannedAt.UTC().Format(time.RFC3339)
		}
		// one series per workload instance; images without instances
		// (--from-sbom) still get a series with empty object labels
		insts := res.Instances
		if len(insts) == 0 {
			insts = []k8s.Instance{{}}
		}
		for _, inst := range insts {
			kind, object := splitController(inst.Controller)
			statusLines = append(statusLines, formatSample("artifactor_image_status", []label{
				{"image", name},
				{"tag", tag},
				{"status", res.Status},
				{"namespace", inst.Namespace},
				{"kind", kind},
				{"object", object},
				{"last_scan", lastScan},
			}))
			for _, c := range cves {
				cveLines = append(cveLines, formatSample("artifactor_image_cve", []label{
					{"image", name},
					{"tag", tag},
					{"cve", c.ID},
					{"severity", c.Severity},
					{"namespace", inst.Namespace},
					{"kind", kind},
					{"object", object},
					{"last_scan", lastScan},
				}))
			}
		}
	}
	sort.Strings(statusLines)
	sort.Strings(cveLines)

	var buf bytes.Buffer
	buf.WriteString("# HELP artifactor_image_status Scan status of each container image known to artifactor, per workload instance (1 = the image is in this state; namespace/kind/object identify the workload running it, empty when there is none; the last_scan label is the image's last successful scan time in RFC3339 UTC, empty when never scanned).\n")
	buf.WriteString("# TYPE artifactor_image_status gauge\n")
	for _, line := range statusLines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	buf.WriteString("# HELP artifactor_image_cve CVE found in a scanned container image, per workload instance running it (1 = present).\n")
	buf.WriteString("# TYPE artifactor_image_cve gauge\n")
	for _, line := range cveLines {
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// dedupeCVEs collapses the CVE matches of one image into one entry per CVE
// ID. A CVE can match several packages of the same image and res.Cves holds
// one entry per (CVE, package) match; since the sample labels do not carry
// the package (that would multiply cardinality), rendering one sample per
// match would emit duplicate series, which Prometheus rejects. When the
// matches of the same CVE disagree, the highest severity wins. The order of
// the first occurrence is kept; the exposition is sorted later anyway.
func dedupeCVEs(cves []scanner.CVE) []scanner.CVE {
	if len(cves) < 2 {
		return cves
	}
	type keptCVE struct {
		index int
		rank  int
	}
	kept := make(map[string]keptCVE, len(cves))
	out := make([]scanner.CVE, 0, len(cves))
	for _, c := range cves {
		rank := severityRank(c.Severity)
		if prev, ok := kept[c.ID]; ok {
			if rank < prev.rank {
				out[prev.index] = c
				kept[c.ID] = keptCVE{index: prev.index, rank: rank}
			}
			continue
		}
		kept[c.ID] = keptCVE{index: len(out), rank: rank}
		out = append(out, c)
	}
	return out
}

// severityRank maps a severity to its position in scanner.SeverityOrder
// (critical first); unknown severities rank last, as in the API/UI.
func severityRank(sev string) int {
	for i, s := range scanner.SeverityOrder {
		if s == sev {
			return i
		}
	}
	return len(scanner.SeverityOrder)
}

// splitController splits a controller reference of the form "kind/name"
// (as recorded by the discovery, e.g. "deployment/api") into the kind and
// object name; a reference without "/" yields an empty kind.
func splitController(controller string) (kind, object string) {
	if i := strings.Index(controller, "/"); i >= 0 {
		return controller[:i], controller[i+1:]
	}
	return "", ""
}

// formatSample renders one exposition line "name{label="value",...} 1" with
// the labels sorted by name for a deterministic output.
func formatSample(name string, labels []label) string {
	sort.Slice(labels, func(i, j int) bool { return labels[i].name < labels[j].name })
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, l := range labels {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(l.name)
		b.WriteString(`="`)
		b.WriteString(escapeLabel(l.value))
		b.WriteByte('"')
	}
	b.WriteString("} 1")
	return b.String()
}

// escapeLabel escapes a label value per the Prometheus text exposition
// format: backslash, double quote and newline.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, "\\\"\n") {
		return v
	}
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}
