//go:build integration

package scanner

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// TestScanAlpineIntegration runs the full syft+grype pipeline against a real
// public image. Requires CIS_TEST_DB_DIR pointing at a directory that
// contains (or can receive) the grype vulnerability database.
//
//	go test -tags integration -run TestScanAlpine -v ./internal/scanner
func TestScanAlpineIntegration(t *testing.T) {
	dbDir := os.Getenv("CIS_TEST_DB_DIR")
	if dbDir == "" {
		t.Skip("set CIS_TEST_DB_DIR to run the integration test")
	}

	provider, status, err := NewProvider(DBOptions{Root: dbDir, AppVersion: "test"})
	if err != nil {
		t.Fatalf("provider: %v (status: %+v)", err, status)
	}

	store := NewStore()
	s := New(Options{
		Provider: provider,
		KeepSBOM: true,
		Platform: "linux/amd64",
		Timeout:  5 * time.Minute,
		Store:    store,
	})

	result := s.scanImage(context.Background(), "alpine:3.20", nil)
	if result.Status != StatusScanned {
		t.Fatalf("scan status = %s: %s", result.Status, result.Error)
	}
	t.Logf("distro: %s", result.Distro)
	t.Logf("artifacts: %d, cves: %d, sbom bytes: %d", len(result.Artifacts), len(result.Cves), len(result.SBOM))
	if len(result.Artifacts) == 0 {
		t.Fatal("no artifacts found — syft pipeline broken")
	}
	if len(result.SBOM) == 0 || !json.Valid(result.SBOM) {
		t.Fatal("syft SBOM was not encoded to valid JSON")
	}
	for _, c := range result.Cves {
		if len(c.ID) == 0 || len(c.PackageName) == 0 {
			t.Fatalf("malformed CVE record: %+v", c)
		}
	}
	limit := 5
	if len(result.Cves) < limit {
		limit = len(result.Cves)
	}
	for _, c := range result.Cves[:limit] {
		t.Logf("  %-18s %-9s %-20s %s", c.ID, c.Severity, c.PackageName, c.PackageVersion)
	}
}
