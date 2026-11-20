package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
)

// testOpenVex is a minimal but valid OpenVEX document (the loader only
// requires valid JSON; the CSAF detector rejects it because it lacks a
// valid "document" object).
const testOpenVex = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/test",
  "author": "test",
  "timestamp": "2026-11-19T00:00:00Z",
  "version": 1,
  "statements": []
}`

func TestResolveVexFiles(t *testing.T) {
	writeIn := func(dir, name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	dir := t.TempDir()
	a := writeIn(dir, "a.vex.json", testOpenVex)
	b := writeIn(dir, "b.vex.json", testOpenVex)
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIn(filepath.Join(dir, "sub"), "nested.vex.json", testOpenVex)

	// a single file resolves to itself
	got, err := ResolveVexFiles([]string{a})
	if err != nil || len(got) != 1 || got[0] != a {
		t.Errorf("ResolveVexFiles(file) = %v, %v; want [%s]", got, err, a)
	}

	// a directory contributes its direct regular files (sorted), skipping
	// the nested subdirectory
	got, err = ResolveVexFiles([]string{dir})
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("ResolveVexFiles(dir) = %v, %v; want [%s %s]", got, err, a, b)
	}

	// multiple paths accumulate
	got, err = ResolveVexFiles([]string{b, a})
	if err != nil || len(got) != 2 || got[0] != a || got[1] != b {
		t.Errorf("ResolveVexFiles(accumulate) = %v, %v; want [%s %s]", got, err, a, b)
	}

	// missing paths fail
	if _, err := ResolveVexFiles([]string{filepath.Join(dir, "nope.json")}); err == nil {
		t.Error("missing path accepted")
	}

	// unsupported formats fail (plain text is neither CSAF nor OpenVEX)
	bad := writeIn(t.TempDir(), "bad.txt", "this is not a vex document")
	if _, err := ResolveVexFiles([]string{bad}); err == nil {
		t.Error("unsupported format accepted")
	}
}

func TestReprocessVex(t *testing.T) {
	store := NewStore()
	store.SetImages([]string{"app:v1", "plain:v1"})
	ms := match.NewMatches()
	ms.Add(match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2026-0001"},
			Metadata:  &vulnerability.Metadata{Severity: "high", Description: "test"},
		},
		Package: pkg.Package{Name: "openssl", Version: "1.0", Type: "deb"},
	})
	scannedAt := time.Now().UTC()
	store.Put(Result{Image: "app:v1", Status: StatusScanned, ScannedAt: &scannedAt, matches: &ms})

	sc := New(Options{Store: store})

	// no VEX documents: the reprocess rebuilds the CVEs from the raw matches
	if err := sc.ReprocessVex(); err != nil {
		t.Fatal(err)
	}
	res := store.Snapshot("app:v1")[0]
	if len(res.Cves) != 1 || res.Cves[0].ID != "CVE-2026-0001" || res.Cves[0].Severity != "high" {
		t.Fatalf("cves after reprocess = %+v", res.Cves)
	}
	if res.Severities["high"] != 1 {
		t.Errorf("severities = %v, want high=1", res.Severities)
	}
	if res.Cves[0].VexStatus != "" || res.Cves[0].VexFile != "" {
		t.Errorf("unexpected vex fields: %+v", res.Cves[0])
	}

	// images without stored matches are left untouched
	store.Put(Result{Image: "plain:v1", Status: StatusError, Error: "no matches"})
	if err := sc.ReprocessVex(); err != nil {
		t.Fatal(err)
	}
	if got := store.Snapshot("plain:v1")[0]; len(got.Cves) != 0 {
		t.Errorf("cves of matchless image = %+v", got.Cves)
	}
}
