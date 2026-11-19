package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getupcloud/artifactor/internal/scanner"
)

func TestParseListen(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "0.0.0.0:9090", false},
		{"0.0.0.0:9090", "0.0.0.0:9090", false},
		{"127.0.0.1", "127.0.0.1:9090", false},
		{":9091", "0.0.0.0:9091", false},
		{"9091", "0.0.0.0:9091", false},
		{"127.0.0.1:9092", "127.0.0.1:9092", false},
		{"localhost:9093", "localhost:9093", false},
		{"[::1]:9091", "[::1]:9091", false},
		{"[::1]", "[::1]:9090", false},
		{"::1", "[::1]:9090", false},
		{"0.0.0.0:0", "0.0.0.0:0", false},
		{" 127.0.0.1:9094 ", "127.0.0.1:9094", false},
		{"0.0.0.0:abc", "", true},
		{"0.0.0.0:65536", "", true},
		{"0.0.0.0:-1", "", true},
		{"[::1", "", true},
		{"[::1]x", "", true},
		{"[::1]extra:9091", "", true},
	}
	for _, tt := range tests {
		got, err := ParseListen(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseListen(%q): expected error, got %q", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseListen(%q): unexpected error: %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseListen(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSplitImageRef(t *testing.T) {
	tests := []struct {
		ref  string
		name string
		tag  string
	}{
		{"nginx", "nginx", ""},
		{"nginx:1.2", "nginx", "1.2"},
		{"registry.exemplo.com:5000/app/api:v1.2.3", "registry.exemplo.com:5000/app/api", "v1.2.3"},
		{"registry.exemplo.com:5000/app/api", "registry.exemplo.com:5000/app/api", ""},
		{"img@sha256:deadbeef", "img", ""},
		{"nginx:1.2@sha256:deadbeef", "nginx", "1.2"},
		{"localhost:5000/nginx", "localhost:5000/nginx", ""},
	}
	for _, tt := range tests {
		name, tag := splitImageRef(tt.ref)
		if name != tt.name || tag != tt.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", tt.ref, name, tag, tt.name, tt.tag)
		}
	}
}

func TestEscapeLabel(t *testing.T) {
	got := escapeLabel("a\\b\"c\nd")
	want := `a\\b\"c\nd`
	if got != want {
		t.Errorf("escapeLabel = %q, want %q", got, want)
	}
	if got := escapeLabel("plain"); got != "plain" {
		t.Errorf("escapeLabel(plain) = %q", got)
	}
}

func TestRender(t *testing.T) {
	store := scanner.NewStore()
	store.SetImages([]string{
		"registry.exemplo.com:5000/app/api:v1.2.3",
		"nginx:latest",
		"img@sha256:deadbeef",
	})
	scannedAt := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	store.Put(scanner.Result{
		Image:     "registry.exemplo.com:5000/app/api:v1.2.3",
		Status:    scanner.StatusScanned,
		ScannedAt: &scannedAt,
		Cves: []scanner.CVE{
			{ID: "CVE-2026-1111", Severity: "critical"},
			{ID: "CVE-2026-2222", Severity: "high"},
		},
	})
	store.Put(scanner.Result{
		Image:     "nginx:latest",
		Status:    scanner.StatusScanned,
		ScannedAt: &scannedAt,
	})

	h := New(store)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

	if got, want := rr.Header().Get("Content-Type"), "text/plain; version=0.0.4; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}

	want := `# HELP artifactor_image_status Scan status of each container image known to artifactor (1 = the image is in this state; the last_scan label is the image's last successful scan time in RFC3339 UTC, empty when never scanned).
# TYPE artifactor_image_status gauge
artifactor_image_status{image="img",last_scan="",status="queued",tag=""} 1
artifactor_image_status{image="nginx",last_scan="2026-11-18T10:00:00Z",status="scanned",tag="latest"} 1
artifactor_image_status{image="registry.exemplo.com:5000/app/api",last_scan="2026-11-18T10:00:00Z",status="scanned",tag="v1.2.3"} 1
# HELP artifactor_image_cve CVE found in a scanned container image (1 = present).
# TYPE artifactor_image_cve gauge
artifactor_image_cve{cve="CVE-2026-1111",image="registry.exemplo.com:5000/app/api",last_scan="2026-11-18T10:00:00Z",severity="critical",tag="v1.2.3"} 1
artifactor_image_cve{cve="CVE-2026-2222",image="registry.exemplo.com:5000/app/api",last_scan="2026-11-18T10:00:00Z",severity="high",tag="v1.2.3"} 1
`
	if got := rr.Body.String(); got != want {
		t.Errorf("metrics output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestNotFound(t *testing.T) {
	h := New(scanner.NewStore())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	if rr.Code != 404 {
		t.Errorf("GET / = %d, want 404", rr.Code)
	}
}

func TestRenderEmptyStore(t *testing.T) {
	h := New(scanner.NewStore())
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if !strings.Contains(body, "# TYPE artifactor_image_status gauge") {
		t.Errorf("empty store should still render the HELP/TYPE headers, got:\n%s", body)
	}
	if strings.Contains(body, "artifactor_image_status{") {
		t.Errorf("empty store should have no samples, got:\n%s", body)
	}
}
