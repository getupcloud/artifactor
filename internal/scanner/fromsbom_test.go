package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/getupcloud/artifactor/internal/logx"
)

// minimalSyftJSON is a small but valid syft-json SBOM (pre-v9 source target
// shape) with a single apk package.
const minimalSyftJSON = `{
  "artifacts": [
    {
      "id": "p1",
      "name": "busybox",
      "version": "1.36.1",
      "type": "apk",
      "foundBy": "apkdb-cataloger",
      "locations": [{"path": "/lib/apk/db/installed"}],
      "licenses": ["GPL-2.0-only"],
      "language": "",
      "cpes": [],
      "purl": "pkg:apk/alpine/busybox@1.36.1-r0?arch=x86_64",
      "metadataType": "apk-db-entry",
      "metadata": {
        "package": "busybox",
        "originPackage": "busybox",
        "version": "1.36.1",
        "architecture": "x86_64",
        "maintainer": "Natanael Copa",
        "installedSize": 0,
        "files": [],
        "pullDependencies": "",
        "pullChecksum": "",
        "gitCommitOfApkPort": ""
      }
    }
  ],
  "source": {"id": "img1", "type": "image", "target": {"userInput": "alpine:3.20"}},
  "distro": {"id": "alpine", "name": "alpine", "versionID": "3.20.0", "idLike": ["alpine"]},
  "descriptor": {"name": "syft", "version": "1.55.0"},
  "schema": {
    "version": "16.0.3",
    "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.0.3.json"
  }
}`

func writeMinimalSBOM(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(minimalSyftJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSBOMInputPaths(t *testing.T) {
	dir := t.TempDir()
	writeMinimalSBOM(t, dir, "b.json")
	writeMinimalSBOM(t, dir, "a.json")
	if err := os.WriteFile(filepath.Join(dir, "note.txt"), []byte("not an sbom"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeMinimalSBOM(t, filepath.Join(dir, "sub"), "nested.json")

	paths, err := sbomInputPaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(dir, "a.json"),
		filepath.Join(dir, "b.json"),
		filepath.Join(dir, "note.txt"),
	}
	if len(paths) != len(want) {
		t.Fatalf("paths = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Fatalf("paths = %v, want %v (non-recursive and sorted)", paths, want)
		}
	}

	// a single file is returned as-is
	single, err := sbomInputPaths(filepath.Join(dir, "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(single) != 1 || single[0] != filepath.Join(dir, "a.json") {
		t.Fatalf("single file paths = %v", single)
	}

	// missing input errors
	if _, err := sbomInputPaths(filepath.Join(dir, "nope.json")); err == nil {
		t.Error("sbomInputPaths on a missing path returned no error")
	}
}

func TestSBOMImageName(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalSBOM(t, dir, "alpine.sbom.json")

	sbo, err := decodeSBOMFile(path)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := sbomImageName(*sbo); got != "alpine:3.20" {
		t.Errorf("sbomImageName = %q, want %q", got, "alpine:3.20")
	}
	if got := sbomNameFromPath("/tmp/x/alpine.sbom.json"); got != "alpine.sbom" {
		t.Errorf("sbomNameFromPath = %q, want %q", got, "alpine.sbom")
	}

	// non-SBOM files fail to decode
	bad := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(bad, []byte("not an sbom"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeSBOMFile(bad); err == nil {
		t.Error("decodeSBOMFile on a non-SBOM file returned no error")
	}
}

func TestScanSBOMFileSkipsSyft(t *testing.T) {
	dir := t.TempDir()
	path := writeMinimalSBOM(t, dir, "alpine.sbom.json")

	logx.Set(logx.LevelErr) // silence the decode warnings of this test
	defer logx.Set(logx.LevelInfo)

	s := New(Options{
		Store:   NewStore(),
		Timeout: time.Minute,
	})
	// No provider set: decoding, naming and artifact extraction must still
	// happen; only the grype matching step reports the missing DB.
	res := s.scanSBOMFile(context.Background(), path)
	if res.Status != StatusError {
		t.Fatalf("status = %s, want error (no vulnerability provider)", res.Status)
	}
	if !strings.Contains(res.Error, "vulnerability database unavailable") {
		t.Errorf("error = %q, want mention of the unavailable DB", res.Error)
	}
	if res.Image != "alpine:3.20" {
		t.Errorf("image = %q, want %q", res.Image, "alpine:3.20")
	}
	if len(res.Artifacts) != 1 || res.Artifacts[0].Name != "busybox" {
		t.Errorf("artifacts = %+v, want the busybox package", res.Artifacts)
	}
	if res.Distro == "" {
		t.Error("distro not extracted from the SBOM")
	}

	// an undecodable file is reported as a failed result, not a panic
	bad := filepath.Join(dir, "note.txt")
	if err := os.WriteFile(bad, []byte("not an sbom"), 0o644); err != nil {
		t.Fatal(err)
	}
	res = s.scanSBOMFile(context.Background(), bad)
	if res.Status != StatusError || res.Image != "note" {
		t.Errorf("bad file result = %+v, want an error result named from the file", res)
	}
}
