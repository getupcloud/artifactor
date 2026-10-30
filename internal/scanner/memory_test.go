//go:build integration

package scanner

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

// TestScanMemoryRelease scans the same image repeatedly and checks that the
// heap settles after garbage collection instead of growing per scan (i.e.
// that syft/grype release per-scan memory). Each round uses a fresh Store so
// result data (SBOM bytes, artifacts, CVEs) does not accumulate on purpose.
//
//	go test -tags integration -run TestScanMemoryRelease -v ./internal/scanner
func TestScanMemoryRelease(t *testing.T) {
	dbDir := os.Getenv("CIS_TEST_DB_DIR")
	if dbDir == "" {
		t.Skip("set CIS_TEST_DB_DIR to run the integration test")
	}
	provider, status, err := NewProvider(DBOptions{Root: dbDir, AppVersion: "test"})
	if err != nil {
		t.Fatalf("provider: %v (status: %+v)", err, status)
	}

	ctx := context.Background()
	heapMB := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc >> 20
	}

	const rounds = 4
	heaps := make([]uint64, rounds)
	for i := 0; i < rounds; i++ {
		// fresh store: keep only the scanner's own state between rounds
		s := New(Options{
			Provider: provider,
			Platform: "linux/amd64",
			Timeout:  5 * time.Minute,
			Store:    NewStore(),
		})
		result := s.scanImage(ctx, "alpine:3.20", nil)
		if result.Status != StatusScanned {
			t.Fatalf("round %d: scan status = %s: %s", i+1, result.Status, result.Error)
		}
		heaps[i] = heapMB()
		t.Logf("round %d: heap after GC = %d MB (artifacts=%d, cves=%d, sbom=%d KB)",
			i+1, heaps[i], len(result.Artifacts), len(result.Cves), len(result.SBOM)>>10)
	}

	// The first round pays one-time costs (lazy init of libraries, caches).
	// Rounds 2..N must settle: the last round may not exceed the second by
	// more than 50% plus a 64 MB slack.
	baseline := heaps[1]
	last := heaps[rounds-1]
	t.Logf("baseline (round 2) = %d MB, last round = %d MB", baseline, last)
	if last > baseline+baseline/2+64 {
		t.Fatalf("heap keeps growing per scan: round2=%d MB, last=%d MB", baseline, last)
	}
}
