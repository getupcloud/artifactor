package scanner

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/anchore/grype/grype/db/v6/distribution"
)

const testListingJSON = `{
 "status": "active",
 "schemaVersion": "v6.1.10",
 "built": "2026-10-30T06:23:28Z",
 "path": "vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst",
 "checksum": "sha256:1e1b9cf2cbfaf16b770e4d75d7beb4840dc4254ca2281682fe5ec3700a4251a8"
}`

func TestListingURL(t *testing.T) {
	got := listingURL("https://grype.anchore.io/databases")
	want := "https://grype.anchore.io/databases/v6/latest.json"
	if got != want {
		t.Fatalf("listingURL = %q, want %q", got, want)
	}
	if got := listingURL("https://grype.anchore.io/databases/"); got != want {
		t.Fatalf("listingURL = %q, want %q", got, want)
	}
}

func TestResolveArchiveURL(t *testing.T) {
	latest, err := distribution.NewLatestFromReader(strings.NewReader(testListingJSON))
	if err != nil {
		t.Fatal(err)
	}
	got, err := resolveArchiveURL(listingURL("https://grype.anchore.io/databases"), latest.Archive)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst"
	if got != want {
		t.Fatalf("resolveArchiveURL = %q, want %q", got, want)
	}
}

func TestFetchLatestListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/databases/v6/latest.json" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, testListingJSON)
	}))
	defer srv.Close()

	client, err := directDBClient(false, "")
	if err != nil {
		t.Fatal(err)
	}
	latest, err := fetchLatestListing(client, srv.URL+"/databases/v6/latest.json", "test")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Status != "active" {
		t.Errorf("status = %q, want active", latest.Status)
	}
	if got, want := latest.SchemaVersion.String(), "v6.1.10"; got != want {
		t.Errorf("schemaVersion = %q, want %q", got, want)
	}
	if got, want := latest.Path, "vulnerability-db_v6.1.10_2026-10-30T00:25:15Z_1793341408.tar.zst"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	if !latest.Built.IsZero() {
		t.Logf("built = %s", latest.Built)
	} else {
		t.Error("built time not parsed")
	}

	// non-200 response
	if _, err := fetchLatestListing(client, srv.URL+"/missing", "test"); err == nil {
		t.Error("expected error for 404 listing")
	}
}

func TestFetchLatestListingInsecureSkipTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, testListingJSON)
	}))
	defer srv.Close()

	// self-signed cert: fails with verification enabled
	secureClient, err := directDBClient(false, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchLatestListing(secureClient, srv.URL, "test"); err == nil {
		t.Error("expected TLS verification error against self-signed server")
	}

	// --insecure-skip-tls: succeeds
	insecureClient, err := directDBClient(true, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchLatestListing(insecureClient, srv.URL, "test"); err != nil {
		t.Errorf("insecure client should accept the self-signed cert: %v", err)
	}

	// --db-ca-cert with the server certificate: succeeds
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caPath := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	caClient, err := directDBClient(false, caPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetchLatestListing(caClient, srv.URL, "test"); err != nil {
		t.Errorf("CA-cert client should accept the server cert: %v", err)
	}
}

func TestDirectDBClientErrors(t *testing.T) {
	if _, err := directDBClient(false, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing CA file")
	}
	empty := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(empty, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := directDBClient(false, empty); err == nil {
		t.Error("expected error for CA file without certificates")
	}
}

func TestDownloadFileChecksum(t *testing.T) {
	content := []byte("fake vulnerability database payload")
	sum := sha256.Sum256(content)
	checksum := "sha256:" + hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Write(content)
	}))
	defer srv.Close()

	client, err := directDBClient(false, "")
	if err != nil {
		t.Fatal(err)
	}

	// correct checksum
	f, err := os.CreateTemp(t.TempDir(), "db-*")
	if err != nil {
		t.Fatal(err)
	}
	if err := downloadFile(client, srv.URL, checksum, f); err != nil {
		t.Fatalf("downloadFile: %v", err)
	}
	f.Close()
	got, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded content mismatch")
	}

	// wrong checksum
	f2, err := os.CreateTemp(t.TempDir(), "db-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f2.Close()
	if err := downloadFile(client, srv.URL, "sha256:"+strings.Repeat("0", 64), f2); err == nil {
		t.Error("expected checksum mismatch error")
	}

	// non-200 response
	f3, err := os.CreateTemp(t.TempDir(), "db-*")
	if err != nil {
		t.Fatal(err)
	}
	defer f3.Close()
	if err := downloadFile(client, srv.URL+"/missing", checksum, f3); err == nil {
		t.Error("expected error for 404 download")
	}
}

type testTarEntry struct {
	name     string
	typeflag byte
	linkname string
	data     []byte
}

func writeZstdTar(t *testing.T, path string, entries []testTarEntry) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw, err := zstd.NewWriter(f)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Size:     int64(len(e.data)),
			Mode:     0o644,
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestExtractZstdTar(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "db.tar.zst")
	writeZstdTar(t, archive, []testTarEntry{
		{name: "vulnerability.db", typeflag: tar.TypeReg, data: []byte("sqlite-ish bytes")},
		{name: "metadata.json", typeflag: tar.TypeReg, data: []byte(`{"schemaVersion":"v6.1.10"}`)},
		{name: "sub", typeflag: tar.TypeDir},
		{name: "sub/extra.json", typeflag: tar.TypeReg, data: []byte(`{}`)},
	})

	dest := filepath.Join(tmp, "out")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extractZstdTar(archive, dest); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"vulnerability.db": "sqlite-ish bytes",
		"metadata.json":    `{"schemaVersion":"v6.1.10"}`,
		"sub/extra.json":   `{}`,
	} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("extracted %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestExtractZstdTarTraversal(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "db.tar.zst")
	writeZstdTar(t, archive, []testTarEntry{
		{name: "../evil.txt", typeflag: tar.TypeReg, data: []byte("nope")},
		{name: "vulnerability.db", typeflag: tar.TypeReg, data: []byte("ok")},
	})

	dest := filepath.Join(tmp, "out")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extractZstdTar(archive, dest); err == nil {
		t.Fatal("expected error for path traversal entry")
	}
	if _, err := os.Stat(filepath.Join(tmp, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal entry was written outside the destination")
	}
	if _, err := os.Stat(filepath.Join(dest, "vulnerability.db")); !os.IsNotExist(err) {
		t.Fatal("no files should be extracted after a traversal attempt")
	}
}

func TestExtractZstdTarSkipsLinks(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "db.tar.zst")
	writeZstdTar(t, archive, []testTarEntry{
		{name: "vulnerability.db", typeflag: tar.TypeReg, data: []byte("ok")},
		{name: "link", typeflag: tar.TypeSymlink, linkname: "vulnerability.db"},
		{name: "hard", typeflag: tar.TypeLink, linkname: "vulnerability.db"},
	})

	dest := filepath.Join(tmp, "out")
	if err := os.Mkdir(dest, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := extractZstdTar(archive, dest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"link", "hard"} {
		if fi, err := os.Lstat(filepath.Join(dest, name)); err == nil {
			t.Fatalf("link %s was extracted (mode %v)", name, fi.Mode())
		}
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:          "0 B",
		1023:       "1023 B",
		1024:       "1.0 KiB",
		197159249:  "188.0 MiB",
		2554044416: "2.4 GiB",
	}
	for n, want := range cases {
		if got := humanSize(n); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
