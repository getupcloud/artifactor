package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/scanner"
)

func testServer(t *testing.T) (*Server, *scanner.Store) {
	t.Helper()
	store := scanner.NewStore()
	store.SetImages([]string{"busybox:1.36", "ghcr.io/org/app:v1", "nginx:1.25"})

	now := time.Now().UTC()
	store.Put(scanner.Result{
		Image: "nginx:1.25", Status: scanner.StatusScanned, ScannedAt: &now, Distro: "debian 12",
		Instances: []k8s.Instance{
			{Namespace: "web", Controller: "deployment/nginx"},
			{Namespace: "ingress", Controller: "daemonset/edge-nginx"},
		},
		Artifacts: []scanner.Artifact{
			{Name: "libssl3", Version: "3.0.11", Type: "deb"},
			{Name: "nginx", Version: "1.25.3", Type: "deb"},
		},
		Cves: []scanner.CVE{
			{ID: "CVE-2024-0001", Severity: "critical", PackageName: "libssl3", PackageVersion: "3.0.11", PackageType: "deb", FixedIn: []string{"3.0.13"}, Description: "openssl bug"},
			{ID: "CVE-2024-0002", Severity: "medium", PackageName: "nginx", PackageVersion: "1.25.3", PackageType: "deb"},
		},
	})
	store.Put(scanner.Result{
		Image: "ghcr.io/org/app:v1", Status: scanner.StatusError, Error: "registry unreachable",
	})
	store.Put(scanner.Result{
		Image: "busybox:1.36", Status: scanner.StatusScanned, ScannedAt: &now,
		Instances: []k8s.Instance{{Namespace: "default", Controller: "statefulset/busybox"}},
		Artifacts: []scanner.Artifact{{Name: "busybox", Version: "1.36.1", Type: "apk"}},
		Cves: []scanner.CVE{
			{ID: "CVE-2023-9999", Severity: "high", PackageName: "busybox", PackageVersion: "1.36.1", PackageType: "apk"},
			// same CVE also present in nginx:1.25 to exercise the image list
			{ID: "CVE-2024-0002", Severity: "medium", PackageName: "busybox", PackageVersion: "1.36.1", PackageType: "apk"},
		},
	})

	srv := New(Options{
		Store: store,
		SPA:   []byte("<!-- EXPORT_DATA -->"),
		Mode:  "test",
		DB:    func() scanner.DBStatus { return scanner.DBStatus{Dir: "/tmp/db", SchemaVersion: "6.1.10"} },
	})
	return srv, store
}

func getJSON(t *testing.T, h http.Handler, path string) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s -> %d: %s", path, rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: bad JSON: %v (%s)", path, err, rec.Body.String())
	}
	return out
}

func getJSONStrings(t *testing.T, h http.Handler, path string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s -> %d: %s", path, rec.Code, rec.Body.String())
	}
	var out []string
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET %s: bad JSON: %v (%s)", path, err, rec.Body.String())
	}
	return out
}

func TestImagesSummary(t *testing.T) {
	srv, _ := testServer(t)
	images := getJSON(t, srv.Handler(), "/api/images")
	if len(images) != 3 {
		t.Fatalf("got %d images, want 3", len(images))
	}
	if images[0]["image"] != "busybox:1.36" { // sorted
		t.Errorf("first image = %v, want busybox:1.36", images[0]["image"])
	}
}

func TestCVEArtifactFilter(t *testing.T) {
	srv, _ := testServer(t)
	// filter by artifact (syft package) name: only libssl3 matches "ssl"
	rows := getJSON(t, srv.Handler(), "/api/cves?artifact=ssl")
	if len(rows) != 1 || rows[0]["id"] != "CVE-2024-0001" {
		t.Fatalf("artifact=ssl rows = %v", rows)
	}
	// case-insensitive
	rows = getJSON(t, srv.Handler(), "/api/cves?artifact=NGINX")
	if len(rows) != 1 || rows[0]["id"] != "CVE-2024-0002" {
		t.Fatalf("artifact=NGINX rows = %v", rows)
	}
}

func TestCVESeverityExclude(t *testing.T) {
	srv, _ := testServer(t)
	// chips start all "on": excluding critical removes only critical rows
	rows := getJSON(t, srv.Handler(), "/api/cves?exclude=critical")
	if len(rows) != 3 { // 4 total minus CVE-2024-0001
		t.Fatalf("exclude=critical rows = %d, want 3", len(rows))
	}
	for _, r := range rows {
		if r["severity"] == "critical" {
			t.Errorf("critical row leaked: %v", r)
		}
	}
	// excluding several severities drops all matching rows
	rows = getJSON(t, srv.Handler(), "/api/cves?exclude=critical,high,medium")
	if len(rows) != 0 {
		t.Fatalf("exclude=critical,high,medium rows = %d, want 0", len(rows))
	}
	// include list still works alongside
	rows = getJSON(t, srv.Handler(), "/api/cves?severity=medium&exclude=medium")
	if len(rows) != 0 {
		t.Fatalf("severity=medium&exclude=medium rows = %d, want 0", len(rows))
	}
}

func TestCVESeverityAndImageFilter(t *testing.T) {
	srv, _ := testServer(t)
	rows := getJSON(t, srv.Handler(), "/api/cves?severity=critical,high")
	if len(rows) != 2 {
		t.Fatalf("severity filter rows = %v", rows)
	}
	// severity ordering: critical before high
	if rows[0]["severity"] != "critical" {
		t.Errorf("first row severity = %v, want critical", rows[0]["severity"])
	}
	rows = getJSON(t, srv.Handler(), "/api/cves?image=nginx:1.25")
	if len(rows) != 2 {
		t.Fatalf("image filter rows = %v", rows)
	}
	for _, r := range rows {
		if r["image"] != "nginx:1.25" {
			t.Errorf("row image = %v", r["image"])
		}
	}
	// error-status images contribute no CVEs
	rows = getJSON(t, srv.Handler(), "/api/cves?image=ghcr.io/org/app:v1")
	if len(rows) != 0 {
		t.Fatalf("error image rows = %v", rows)
	}
}

func TestCVEFixedFilter(t *testing.T) {
	srv, _ := testServer(t)
	// fixture: only CVE-2024-0001 (libssl3) has FixedIn set
	rows := getJSON(t, srv.Handler(), "/api/cves?fixed=1")
	if len(rows) != 1 || rows[0]["id"] != "CVE-2024-0001" {
		t.Fatalf("fixed=1 rows = %v, want only CVE-2024-0001", rows)
	}
	for _, r := range rows {
		if len(r["fixedIn"].([]any)) == 0 {
			t.Errorf("row without fix leaked: %v", r)
		}
	}
	// without the flag all 4 rows come back
	if rows := getJSON(t, srv.Handler(), "/api/cves"); len(rows) != 4 {
		t.Fatalf("unfiltered rows = %d, want 4", len(rows))
	}
}

func TestCVEImagesList(t *testing.T) {
	srv, _ := testServer(t)
	rows := getJSON(t, srv.Handler(), "/api/cves")
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r["id"].(string)] = r
	}
	// CVE-2024-0002 lives in both nginx and busybox; nginx has 2 instances
	imgs, _ := byID["CVE-2024-0002"]["images"].([]any)
	if len(imgs) != 3 {
		t.Fatalf("CVE-2024-0002 images = %v, want 3 entries (2 nginx instances + busybox)", imgs)
	}
	found := map[string]bool{}
	for _, img := range imgs {
		entry := img.(map[string]any)
		found[entry["image"].(string)] = true
		if entry["image"] == "busybox:1.36" {
			if entry["namespace"] != "default" || entry["controller"] != "statefulset/busybox" {
				t.Errorf("busybox entry = %v", entry)
			}
		}
		if entry["image"] == "nginx:1.25" && entry["namespace"] == "web" {
			if entry["controller"] != "deployment/nginx" {
				t.Errorf("nginx web entry = %v", entry)
			}
		}
	}
	if !found["nginx:1.25"] || !found["busybox:1.36"] {
		t.Fatalf("images = %v", imgs)
	}
	// CVE-2024-0001 only in nginx (2 instances)
	imgs, _ = byID["CVE-2024-0001"]["images"].([]any)
	if len(imgs) != 2 {
		t.Fatalf("CVE-2024-0001 images = %v", imgs)
	}
}

func TestArtifactsEndpoint(t *testing.T) {
	srv, _ := testServer(t)
	names := getJSONStrings(t, srv.Handler(), "/api/artifacts")
	if len(names) != 3 { // libssl3, nginx, busybox
		t.Fatalf("artifact names = %v", names)
	}
	names = getJSONStrings(t, srv.Handler(), "/api/artifacts?image=busybox:1.36")
	if len(names) != 1 || names[0] != "busybox" {
		t.Fatalf("per-image artifacts = %v", names)
	}
	names = getJSONStrings(t, srv.Handler(), "/api/artifacts?q=ssl")
	if len(names) != 1 || names[0] != "libssl3" {
		t.Fatalf("q=ssl artifacts = %v", names)
	}
}

func TestExportEndpoint(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/export", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("export -> %d: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q", cd)
	}
	body := rec.Body.String()
	if strings.Contains(body, "<!-- EXPORT_DATA -->") {
		t.Error("export marker was not replaced")
	}
	const prefix = `<script id="__artifactor_data" type="application/json">`
	i := strings.Index(body, prefix)
	if i < 0 {
		t.Fatal("exported HTML missing embedded snapshot script")
	}
	j := strings.Index(body[i:], "</script>")
	if j < 0 {
		t.Fatal("snapshot script not closed")
	}
	var snap struct {
		GeneratedAt string           `json:"generatedAt"`
		Images      []map[string]any `json:"images"`
		Cves        []map[string]any `json:"cves"`
	}
	if err := json.Unmarshal([]byte(body[i+len(prefix):i+j]), &snap); err != nil {
		t.Fatalf("snapshot JSON invalid: %v", err)
	}
	if len(snap.Images) != 3 {
		t.Errorf("snapshot images = %d, want 3", len(snap.Images))
	}
	if len(snap.Cves) != 4 { // 2 in nginx + 2 in busybox
		t.Errorf("snapshot cves = %d, want 4", len(snap.Cves))
	}
	if snap.GeneratedAt == "" {
		t.Error("snapshot missing generatedAt")
	}
}

func TestStatusEndpoint(t *testing.T) {
	srv, store := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	var status map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status["mode"] != "test" {
		t.Errorf("mode = %v", status["mode"])
	}
	store.SetDBError("boom")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &status)
	db := status["db"].(map[string]any)
	if db["error"] != "boom" {
		t.Errorf("db error = %v", db["error"])
	}
}
