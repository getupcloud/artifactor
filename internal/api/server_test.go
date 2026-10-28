package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		SBOM: []byte(`{"artifacts":[{"name":"nginx"}]}`),
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

	namesJSON, err := os.ReadFile("../../web/names.json")
	if err != nil {
		t.Fatalf("read web/names.json: %v", err)
	}
	srv := New(Options{
		Store:     store,
		SPA:       []byte("<!-- EXPORT_DATA -->"),
		NamesJSON: namesJSON,
		Mode:      "test",
		DB:        func() scanner.DBStatus { return scanner.DBStatus{Dir: "/tmp/db", SchemaVersion: "6.1.10"} },
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

func TestNamespaceEndpointAndFilter(t *testing.T) {
	srv, _ := testServer(t)
	names := getJSONStrings(t, srv.Handler(), "/api/namespaces")
	want := []string{"default", "ingress", "web"}
	if len(names) != 3 || names[0] != want[0] || names[1] != want[1] || names[2] != want[2] {
		t.Fatalf("namespaces = %v, want %v", names, want)
	}

	// web: CVE-2024-0001 (nginx web+ingress) and CVE-2024-0002 (nginx web + busybox default)
	if rows := getJSON(t, srv.Handler(), "/api/cves?namespace=web"); len(rows) != 2 {
		t.Fatalf("namespace=web rows = %d, want 2", len(rows))
	}
	// default: the two busybox CVEs (busybox runs in default; nginx does not)
	rows := getJSON(t, srv.Handler(), "/api/cves?namespace=default")
	if len(rows) != 2 {
		t.Fatalf("namespace=default rows = %d, want 2", len(rows))
	}
	for _, r := range rows {
		if r["image"] != "busybox:1.36" {
			t.Errorf("unexpected row for namespace=default: %v", r)
		}
	}
	// unknown namespace: nothing
	if rows := getJSON(t, srv.Handler(), "/api/cves?namespace=nope"); len(rows) != 0 {
		t.Fatalf("namespace=nope rows = %d, want 0", len(rows))
	}
}

func TestFetchNamedVulns(t *testing.T) {
	srv, _ := testServer(t)

	// failure at startup: the embedded copy stays in place
	srv.opts.NamesURL = "http://127.0.0.1:1/nope"
	if err := srv.FetchNamedVulns(context.Background()); err == nil {
		t.Fatal("expected fetch error for unreachable URL")
	}
	groups := getJSON(t, srv.Handler(), "/api/named-vulns")
	if len(groups) != 4 || groups[0]["name"] != "PHP2Shell" {
		t.Fatalf("groups after failed fetch = %v", groups)
	}

	// success: the fetched list replaces the embedded one
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"NewShell","cves":["CVE-1"]}]`))
	}))
	defer remote.Close()
	srv.opts.NamesURL = remote.URL
	if err := srv.FetchNamedVulns(context.Background()); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	groups = getJSON(t, srv.Handler(), "/api/named-vulns")
	if len(groups) != 1 || groups[0]["name"] != "NewShell" {
		t.Fatalf("groups after fetch = %v", groups)
	}

	// failure after a successful fetch: the last known-good list stays
	srv.opts.NamesURL = "http://127.0.0.1:1/nope"
	if err := srv.FetchNamedVulns(context.Background()); err == nil {
		t.Fatal("expected fetch error for unreachable URL")
	}
	groups = getJSON(t, srv.Handler(), "/api/named-vulns")
	if len(groups) != 1 || groups[0]["name"] != "NewShell" {
		t.Fatalf("groups after later failed fetch = %v", groups)
	}
}

func TestNamedVulnsEndpoint(t *testing.T) {
	srv, _ := testServer(t)
	groups := getJSON(t, srv.Handler(), "/api/named-vulns")
	if len(groups) != 4 {
		t.Fatalf("named vulns = %d entries, want 4", len(groups))
	}
	if groups[0]["name"] != "PHP2Shell" {
		t.Errorf("first group = %v", groups[0])
	}
	php := groups[0]["cves"].([]any)
	if len(php) != 3 {
		t.Errorf("php2shell cves = %v, want 3", php)
	}
	if groups[3]["name"] != "Log4Shell" {
		t.Errorf("last group = %v", groups[3])
	}
}

func TestCVEMultipleIDFilter(t *testing.T) {
	srv, _ := testServer(t)
	// two IDs separated by spaces (URL-encoded as +): OR semantics
	rows := getJSON(t, srv.Handler(), "/api/cves?id=CVE-2024-0001+CVE-2023-9999")
	if len(rows) != 2 {
		t.Fatalf("multi-id rows = %d, want 2", len(rows))
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r["id"].(string)] = true
	}
	if !seen["CVE-2024-0001"] || !seen["CVE-2023-9999"] {
		t.Fatalf("multi-id rows = %v", rows)
	}
	// substring matching still works per token
	rows = getJSON(t, srv.Handler(), "/api/cves?id=CVE-2024-0001+CVE-2024-9999")
	if len(rows) != 1 || rows[0]["id"] != "CVE-2024-0001" {
		t.Fatalf("partial-token rows = %v", rows)
	}
	// whitespace-only input behaves like no filter
	if rows := getJSON(t, srv.Handler(), "/api/cves?id=+++"); len(rows) != 4 {
		t.Fatalf("blank id rows = %d, want 4", len(rows))
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

func TestCVEsCSV(t *testing.T) {
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/cves.csv", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv -> %d: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("content type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("content disposition = %q", cd)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 5 { // header + 4 CVE rows
		t.Fatalf("csv lines = %d, want 5:\n%s", len(lines), rec.Body.String())
	}
	if !strings.Contains(lines[0], "CVE") || !strings.Contains(lines[0], "Fixed In") {
		t.Errorf("header = %q", lines[0])
	}
	found := false
	for _, l := range lines[1:] {
		if strings.Contains(l, "CVE-2024-0001") {
			found = true
			if !strings.Contains(l, "3.0.13") || !strings.Contains(l, "critical") {
				t.Errorf("row = %q", l)
			}
		}
	}
	if !found {
		t.Error("CVE-2024-0001 missing from CSV")
	}

	// filters apply: only nginx rows
	req = httptest.NewRequest(http.MethodGet, "/api/cves.csv?image=nginx:1.25", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	lines = strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 3 { // header + 2 rows
		t.Fatalf("filtered csv lines = %d, want 3", len(lines))
	}
	for _, l := range lines[1:] {
		if !strings.Contains(l, "nginx:1.25") {
			t.Errorf("filtered row = %q", l)
		}
	}
}

func TestExportCVEsCSVFile(t *testing.T) {
	srv, _ := testServer(t)
	path := filepath.Join(t.TempDir(), "scan.csv")
	if err := srv.ExportCVEsCSV(path); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("exported csv lines = %d, want 5", len(lines))
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
		Namespaces  []string         `json:"namespaces"`
		NamedVulns  []map[string]any `json:"namedVulns"`
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
	if len(snap.Namespaces) != 3 {
		t.Errorf("snapshot namespaces = %v, want 3", snap.Namespaces)
	}
	if len(snap.NamedVulns) != 4 {
		t.Errorf("snapshot namedVulns = %v, want 4", snap.NamedVulns)
	}
	if snap.GeneratedAt == "" {
		t.Error("snapshot missing generatedAt")
	}
}

func TestExportSBOMsAndGrype(t *testing.T) {
	srv, _ := testServer(t)

	dir := t.TempDir()
	n, err := srv.ExportSBOMs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 { // only nginx carries SBOM bytes in the fixture
		t.Fatalf("sbom files = %d, want 1", n)
	}
	data, err := os.ReadFile(filepath.Join(dir, "nginx_1.25.sbom.json"))
	if err != nil {
		t.Fatalf("read sbom file: %v (dir contents: %v)", err, mustGlob(t, dir))
	}
	if string(data) != `{"artifacts":[{"name":"nginx"}]}` {
		t.Errorf("sbom content = %s", data)
	}

	gdir := t.TempDir()
	n, err = srv.ExportGrype(gdir)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 { // nginx + busybox are scanned
		t.Fatalf("grype files = %d, want 2", n)
	}
	data, err = os.ReadFile(filepath.Join(gdir, "nginx_1.25.grype.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Fix      struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"artifact"`
		} `json:"matches"`
		Distro struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"distro"`
		Source struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"source"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("grype report JSON: %v", err)
	}
	if len(report.Matches) != 2 {
		t.Fatalf("grype matches = %d, want 2", len(report.Matches))
	}
	first := report.Matches[0]
	if first.Vulnerability.ID != "CVE-2024-0001" || first.Vulnerability.Fix.State != "fixed" ||
		len(first.Vulnerability.Fix.Versions) != 1 || first.Vulnerability.Fix.Versions[0] != "3.0.13" {
		t.Errorf("first match = %+v", first)
	}
	if report.Source.Type != "image" || report.Source.Target != "nginx:1.25" {
		t.Errorf("source = %+v", report.Source)
	}
	if report.Distro.Name != "debian" {
		t.Errorf("distro = %+v", report.Distro)
	}
}

func mustGlob(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestExportAll(t *testing.T) {
	srv, _ := testServer(t)
	dir := t.TempDir()
	htmlPath, csvPath, sbomCount, grypeCount, err := srv.ExportAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if htmlPath != filepath.Join(dir, "scan.html") {
		t.Errorf("html path = %s", htmlPath)
	}
	if csvPath != filepath.Join(dir, "scan.csv") {
		t.Errorf("csv path = %s", csvPath)
	}
	if sbomCount != 1 || grypeCount != 2 {
		t.Errorf("counts = sbom %d grype %d, want 1/2", sbomCount, grypeCount)
	}
	for _, rel := range []string{"scan.html", "scan.csv", "sbom", "grype"} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("missing %s in export dir: %v", rel, err)
		}
	}
	csvData, err := os.ReadFile(csvPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(csvData)), "\n")
	if len(lines) != 5 { // header + 4 rows
		t.Errorf("exported scan.csv lines = %d, want 5", len(lines))
	}
}

func TestStatusEndpoint(t *testing.T) {
	srv, store := testServer(t)
	srv.opts.CustomerName = "Acme"
	srv.opts.ClusterName = "prod-eks"
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
	if status["customer"] != "Acme" || status["cluster"] != "prod-eks" {
		t.Errorf("customer/cluster = %v/%v", status["customer"], status["cluster"])
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
