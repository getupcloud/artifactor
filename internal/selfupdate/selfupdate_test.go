package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    bool
		wantErr bool
	}{
		{name: "newer patch", current: "0.4.5", latest: "0.4.6", want: true},
		{name: "newer minor", current: "0.4.5", latest: "0.5.0", want: true},
		{name: "newer major", current: "0.4.5", latest: "1.0.0", want: true},
		{name: "equal", current: "0.4.5", latest: "0.4.5", want: false},
		{name: "older", current: "0.5.0", latest: "0.4.9", want: false},
		{name: "v prefix on both", current: "v0.4.5", latest: "v0.4.6", want: true},
		{name: "v prefix on latest only", current: "0.4.5", latest: "v0.4.6", want: true},
		{name: "prerelease is not newer than release", current: "0.5.0", latest: "0.5.0-rc1", want: false},
		{name: "release is newer than prerelease", current: "0.5.0-rc1", latest: "0.5.0", want: true},
		{name: "dev current", current: "dev", latest: "0.4.6", wantErr: true},
		{name: "empty latest", current: "0.4.5", latest: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsNewer(tt.current, tt.latest)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsNewer(%q, %q) error = %v, wantErr %v", tt.current, tt.latest, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("IsNewer(%q, %q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestParseRelease(t *testing.T) {
	body := `{
		"tag_name": "v0.5.0",
		"assets": [
			{"name": "artifactor_linux_arm64.tar.gz", "browser_download_url": "https://example.com/arm64"},
			{"name": "artifactor_linux_amd64.tar.gz", "browser_download_url": "https://example.com/amd64"},
			{"name": "checksums.txt", "browser_download_url": "https://example.com/sums"}
		]
	}`
	rel, err := parseRelease([]byte(body), "linux", "amd64")
	if err != nil {
		t.Fatalf("parseRelease: %v", err)
	}
	if rel.Version != "0.5.0" {
		t.Errorf("Version = %q, want 0.5.0", rel.Version)
	}
	if rel.AssetName != "artifactor_linux_amd64.tar.gz" {
		t.Errorf("AssetName = %q", rel.AssetName)
	}
	if rel.AssetURL != "https://example.com/amd64" {
		t.Errorf("AssetURL = %q", rel.AssetURL)
	}

	// Missing asset for the platform.
	if _, err := parseRelease([]byte(body), "darwin", "amd64"); err == nil {
		t.Error("parseRelease with unmatched platform: expected error")
	}
	// No tag.
	if _, err := parseRelease([]byte(`{"tag_name": "", "assets": []}`), "linux", "amd64"); err == nil {
		t.Error("parseRelease without tag_name: expected error")
	}
	// Invalid JSON.
	if _, err := parseRelease([]byte(`{`), "linux", "amd64"); err == nil {
		t.Error("parseRelease with invalid JSON: expected error")
	}
}

// buildTarGz returns a gzipped tar with the given entries (name -> content).
func buildTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// serveAsset starts an httptest server serving a tarball with the given
// entries and returns its URL.
func serveAsset(t *testing.T, entries map[string]string) *httptest.Server {
	t.Helper()
	archive := buildTarGz(t, entries)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/release/artifactor_linux_amd64.tar.gz" {
			http.NotFound(w, r)
			return
		}
		w.Write(archive)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestApplyReplacesTarget(t *testing.T) {
	srv := serveAsset(t, map[string]string{
		"artifactor": "new-binary",
		"README.md":  "docs",
	})
	rel := &Release{Version: "0.5.0", AssetName: "artifactor_linux_amd64.tar.gz", AssetURL: srv.URL + "/release/artifactor_linux_amd64.tar.gz"}

	dir := t.TempDir()
	target := filepath.Join(dir, "artifactor")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if err := rel.Apply(context.Background(), target, false); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "new-binary" {
		t.Errorf("target content = %q, want new-binary", data)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target: %v", err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("target mode = %v, want 0755", info.Mode().Perm())
	}
	// The staging file must be gone after the rename.
	if _, err := os.Stat(target + ".new"); !os.IsNotExist(err) {
		t.Errorf("staging file %s.new still exists", target)
	}
}

func TestApplyMissingBinaryEntry(t *testing.T) {
	srv := serveAsset(t, map[string]string{"README.md": "docs"})
	rel := &Release{Version: "0.5.0", AssetName: "artifactor_linux_amd64.tar.gz", AssetURL: srv.URL + "/release/artifactor_linux_amd64.tar.gz"}

	dir := t.TempDir()
	target := filepath.Join(dir, "artifactor")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}

	if err := rel.Apply(context.Background(), target, false); err == nil {
		t.Fatal("Apply without artifactor entry: expected error")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "old-binary" {
		t.Errorf("target content = %q, want the original old-binary", data)
	}
}

func TestApplyDownloadError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	rel := &Release{Version: "0.5.0", AssetName: "artifactor_linux_amd64.tar.gz", AssetURL: srv.URL + "/missing"}

	dir := t.TempDir()
	target := filepath.Join(dir, "artifactor")
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := rel.Apply(context.Background(), target, false); err == nil {
		t.Fatal("Apply with 404 asset: expected error")
	}
}
