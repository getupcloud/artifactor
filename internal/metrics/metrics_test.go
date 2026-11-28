package metrics

import (
	"fmt"
	"net/http/httptest"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/getupcloud/artifactor/internal/k8s"
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
		Instances: []k8s.Instance{
			{Namespace: "prod", Controller: "deployment/api"},
			{Namespace: "staging", Controller: "statefulset/api"},
		},
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

	want := `# HELP artifactor_image_status Scan status of each container image known to artifactor, per workload instance (1 = the image is in this state; namespace/kind/object identify the workload running it, empty when there is none; the last_scan label is the image's last successful scan time in RFC3339 UTC, empty when never scanned).
# TYPE artifactor_image_status gauge
artifactor_image_status{image="img",kind="",last_scan="",namespace="",object="",status="queued",tag=""} 1
artifactor_image_status{image="nginx",kind="",last_scan="2026-11-18T10:00:00Z",namespace="",object="",status="scanned",tag="latest"} 1
artifactor_image_status{image="registry.exemplo.com:5000/app/api",kind="deployment",last_scan="2026-11-18T10:00:00Z",namespace="prod",object="api",status="scanned",tag="v1.2.3"} 1
artifactor_image_status{image="registry.exemplo.com:5000/app/api",kind="statefulset",last_scan="2026-11-18T10:00:00Z",namespace="staging",object="api",status="scanned",tag="v1.2.3"} 1
# HELP artifactor_image_cve CVE found in a scanned container image, per workload instance running it (1 = present).
# TYPE artifactor_image_cve gauge
artifactor_image_cve{cve="CVE-2026-1111",image="registry.exemplo.com:5000/app/api",kind="deployment",last_scan="2026-11-18T10:00:00Z",namespace="prod",object="api",severity="critical",tag="v1.2.3"} 1
artifactor_image_cve{cve="CVE-2026-1111",image="registry.exemplo.com:5000/app/api",kind="statefulset",last_scan="2026-11-18T10:00:00Z",namespace="staging",object="api",severity="critical",tag="v1.2.3"} 1
artifactor_image_cve{cve="CVE-2026-2222",image="registry.exemplo.com:5000/app/api",kind="deployment",last_scan="2026-11-18T10:00:00Z",namespace="prod",object="api",severity="high",tag="v1.2.3"} 1
artifactor_image_cve{cve="CVE-2026-2222",image="registry.exemplo.com:5000/app/api",kind="statefulset",last_scan="2026-11-18T10:00:00Z",namespace="staging",object="api",severity="high",tag="v1.2.3"} 1
`
	if got := rr.Body.String(); got != want {
		t.Errorf("metrics output mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRenderDeduplicatesCVEs(t *testing.T) {
	scannedAt := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	instances := []k8s.Instance{
		{Namespace: "prod", Controller: "deployment/api"},
		{Namespace: "staging", Controller: "deployment/api"},
	}
	line := func(namespace, id, severity string) string {
		return fmt.Sprintf(`artifactor_image_cve{cve=%q,image="registry.exemplo.com:5000/app/api",kind="deployment",last_scan="2026-11-18T10:00:00Z",namespace=%q,object="api",severity=%q,tag="v1.2.3"} 1`, id, namespace, severity)
	}
	tests := []struct {
		name string
		cves []scanner.CVE
		want []string
	}{
		{
			name: "same CVE in two packages renders one line per instance",
			cves: []scanner.CVE{
				{ID: "CVE-2026-1111", Severity: "high", PackageName: "openssl", PackageVersion: "3.0.1"},
				{ID: "CVE-2026-1111", Severity: "high", PackageName: "openssl-libs", PackageVersion: "3.0.1"},
			},
			want: []string{
				line("prod", "CVE-2026-1111", "high"),
				line("staging", "CVE-2026-1111", "high"),
			},
		},
		{
			name: "highest severity wins when the matches disagree",
			cves: []scanner.CVE{
				{ID: "CVE-2026-2222", Severity: "low", PackageName: "a"},
				{ID: "CVE-2026-2222", Severity: "critical", PackageName: "b"},
				{ID: "CVE-2026-2222", Severity: "medium", PackageName: "c"},
			},
			want: []string{
				line("prod", "CVE-2026-2222", "critical"),
				line("staging", "CVE-2026-2222", "critical"),
			},
		},
		{
			name: "unknown severity ranks below a known one",
			cves: []scanner.CVE{
				{ID: "CVE-2026-3333", Severity: "unknown", PackageName: "a"},
				{ID: "CVE-2026-3333", Severity: "negligible", PackageName: "b"},
			},
			want: []string{
				line("prod", "CVE-2026-3333", "negligible"),
				line("staging", "CVE-2026-3333", "negligible"),
			},
		},
		{
			name: "distinct CVEs keep one line each",
			cves: []scanner.CVE{
				{ID: "CVE-2026-1111", Severity: "high", PackageName: "a"},
				{ID: "CVE-2026-1111", Severity: "high", PackageName: "b"},
				{ID: "CVE-2026-2222", Severity: "critical", PackageName: "a"},
				{ID: "CVE-2026-3333", Severity: "medium", PackageName: "b"},
			},
			want: []string{
				line("prod", "CVE-2026-1111", "high"),
				line("prod", "CVE-2026-2222", "critical"),
				line("prod", "CVE-2026-3333", "medium"),
				line("staging", "CVE-2026-1111", "high"),
				line("staging", "CVE-2026-2222", "critical"),
				line("staging", "CVE-2026-3333", "medium"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := scanner.NewStore()
			store.SetImages([]string{"registry.exemplo.com:5000/app/api:v1.2.3"})
			store.Put(scanner.Result{
				Image:     "registry.exemplo.com:5000/app/api:v1.2.3",
				Status:    scanner.StatusScanned,
				ScannedAt: &scannedAt,
				Instances: instances,
				Cves:      tt.cves,
			})
			rr := httptest.NewRecorder()
			New(store).ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))

			var got []string
			seen := map[string]bool{}
			for _, l := range strings.Split(rr.Body.String(), "\n") {
				if !strings.HasPrefix(l, "artifactor_image_cve{") {
					continue
				}
				if seen[l] {
					t.Errorf("duplicate series: %s", l)
				}
				seen[l] = true
				got = append(got, l)
			}
			want := append([]string(nil), tt.want...)
			sort.Strings(want)
			if !slices.Equal(got, want) {
				t.Errorf("artifactor_image_cve lines mismatch:\n--- got ---\n%s\n--- want ---\n%s",
					strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

func TestSplitController(t *testing.T) {
	tests := []struct {
		in     string
		kind   string
		object string
	}{
		{"deployment/api", "deployment", "api"},
		{"pod/nginx-abc123", "pod", "nginx-abc123"},
		{"", "", ""},
		{"no-slash", "", ""},
	}
	for _, tt := range tests {
		kind, object := splitController(tt.in)
		if kind != tt.kind || object != tt.object {
			t.Errorf("splitController(%q) = (%q, %q), want (%q, %q)", tt.in, kind, object, tt.kind, tt.object)
		}
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
