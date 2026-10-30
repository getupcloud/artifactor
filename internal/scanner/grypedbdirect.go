package scanner

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/spf13/afero"

	dbv6 "github.com/anchore/grype/grype/db/v6"
	"github.com/anchore/grype/grype/db/v6/distribution"

	"github.com/getupcloud/artifactor/internal/logx"
)

// directUpdate downloads the grype vulnerability DB and its metadata directly
// with net/http (--grype-db-direct-download), instead of using the grype
// download library. It mirrors the curator semantics: the listing
// (latest.json) is fetched, the archive is downloaded only when it is newer
// than the installed database (same schema model required), verified against
// its sha256 checksum, extracted, hydrated and atomically swapped into
// <dbRoot>/v6. It returns whether the installed database changed.
func directUpdate(opts DBOptions) (bool, error) {
	client, err := directDBClient(opts.Insecure, opts.CACert)
	if err != nil {
		return false, err
	}

	baseURL := distribution.DefaultConfig().LatestURL
	latest, err := fetchLatestListing(client, listingURL(baseURL), opts.AppVersion)
	if err != nil {
		return false, err
	}

	// Compare the listing with the installed database (same logic as the
	// curator's isSupersededBy): keep the current DB unless the listing
	// offers a newer build of the same schema model.
	dbFile := filepath.Join(opts.Root, strconv.Itoa(dbv6.ModelVersion), dbv6.VulnerabilityDBFileName)
	current, err := dbv6.ReadDescription(dbFile)
	if err != nil && !errors.Is(err, dbv6.ErrDBDoesNotExist) {
		logx.Warnf("cannot read installed vulnerability database metadata: %v (continuing with update)", err)
		current = nil
	}
	if current != nil {
		if !current.SchemaVersion.Valid() || latest.SchemaVersion.Model != current.SchemaVersion.Model {
			logx.Warnf("listing is for a different DB schema (want %d, have %s); keeping the installed database", latest.SchemaVersion.Model, current.SchemaVersion)
			return false, nil
		}
		if !latest.Built.After(current.Built.Time) {
			logx.Debugf("vulnerability DB already up to date (built %s)", current.Built)
			return false, nil
		}
	}
	if latest.SchemaVersion.Model != dbv6.ModelVersion {
		return false, fmt.Errorf("listing offers DB schema %s but this client supports schema %d", latest.SchemaVersion, dbv6.ModelVersion)
	}

	archiveURL, err := resolveArchiveURL(listingURL(baseURL), latest.Archive)
	if err != nil {
		return false, err
	}

	if err := os.MkdirAll(opts.Root, 0o700); err != nil {
		return false, fmt.Errorf("create db root dir %s: %w", opts.Root, err)
	}

	// 1. Download the archive to a temp file under the DB root (same
	//    filesystem, so the final activation is an atomic rename).
	archivePath, err := os.CreateTemp(opts.Root, "grype-db-archive-*")
	if err != nil {
		return false, fmt.Errorf("create archive temp file: %w", err)
	}
	archiveName := archivePath.Name()
	defer os.Remove(archiveName) // best-effort cleanup
	if err := downloadFile(client, archiveURL, latest.Archive.Checksum, archivePath); err != nil {
		archivePath.Close()
		return false, fmt.Errorf("unable to download vulnerability database: %w", err)
	}
	if err := archivePath.Close(); err != nil {
		return false, fmt.Errorf("close archive temp file: %w", err)
	}

	// 2. Extract the archive into a temp directory under the DB root.
	tempDir, err := os.MkdirTemp(opts.Root, "grype-db-download-")
	if err != nil {
		return false, fmt.Errorf("create extraction temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir) // no-op after a successful activation
	if err := extractZstdTar(archiveName, tempDir); err != nil {
		return false, fmt.Errorf("extract vulnerability database archive: %w", err)
	}

	// 3. Hydrate, record the import metadata and swap into place (the same
	//    steps the curator's activate performs).
	if err := directActivate(opts.Root, tempDir, archiveURL); err != nil {
		return false, err
	}

	logx.Infof("vulnerability DB installed (schema %s, built %s)", latest.SchemaVersion, latest.Built)
	return true, nil
}

// directDBClient builds the HTTP client used by the direct grype DB download.
// With insecure set, TLS certificate verification is skipped
// (--insecure-skip-tls). A non-empty caCert (path to a PEM file) is used
// instead of the system roots when verification is enabled.
func directDBClient(insecure bool, caCert string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if insecure {
		tlsCfg.InsecureSkipVerify = true
	} else if caCert != "" {
		pemBytes, err := os.ReadFile(caCert)
		if err != nil {
			return nil, fmt.Errorf("read --db-ca-cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("read --db-ca-cert: no certificates found in %s", caCert)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			TLSClientConfig:       tlsCfg,
		},
		// no overall timeout: the DB archive can take a while to download
	}, nil
}

// listingURL builds the full URL of the grype DB listing (latest.json) from
// the base database URL (e.g. https://grype.anchore.io/databases).
func listingURL(baseURL string) string {
	u := strings.TrimRight(baseURL, "/")
	return fmt.Sprintf("%s/v%d/%s", u, dbv6.ModelVersion, distribution.LatestFileName)
}

// fetchLatestListing downloads and parses the grype DB listing (latest.json).
func fetchLatestListing(client *http.Client, u, appVersion string) (*distribution.LatestDocument, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build listing request: %w", err)
	}
	req.Header.Set("User-Agent", "artifactor "+appVersion)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download listing %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download listing %s: %s", u, resp.Status)
	}

	latest, err := distribution.NewLatestFromReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parse listing %s: %w", u, err)
	}
	if latest == nil {
		return nil, fmt.Errorf("listing %s is empty", u)
	}
	return latest, nil
}

// resolveArchiveURL builds the full archive download URL from the listing
// URL and the relative archive path (same logic as the grype client's
// ResolveArchiveURL).
func resolveArchiveURL(baseURL string, archive distribution.Archive) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse db URL %q: %w", baseURL, err)
	}
	u.Path = path.Join(path.Dir(u.Path), path.Clean(archive.Path))
	return u.String(), nil
}

// downloadFile downloads archiveURL into the open file f, logs progress, and
// verifies the sha256 checksum (format "sha256:<hex>") when checksum is
// non-empty.
func downloadFile(client *http.Client, archiveURL, checksum string, f *os.File) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, archiveURL, nil)
	if err != nil {
		return fmt.Errorf("build download request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", archiveURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", archiveURL, resp.Status)
	}

	start := time.Now()
	body := &progressBody{body: resp.Body, total: resp.ContentLength, label: "downloading grype DB"}
	hasher := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hasher), body); err != nil {
		return fmt.Errorf("download %s: %w", archiveURL, err)
	}
	logx.Infof("downloaded grype DB (%s) in %s", humanSize(body.read), time.Since(start).Round(time.Second))

	if checksum == "" {
		return nil
	}
	actual := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	if actual != checksum {
		return fmt.Errorf("bad DB archive checksum: want %s, have %s", checksum, actual)
	}
	return nil
}

// progressBody logs download progress at most once every 5 seconds.
type progressBody struct {
	body    io.Reader
	total   int64
	label   string
	read    int64
	lastLog time.Time
}

func (p *progressBody) Read(b []byte) (int, error) {
	n, err := p.body.Read(b)
	p.read += int64(n)
	if p.total > 0 && time.Since(p.lastLog) >= 5*time.Second {
		p.lastLog = time.Now()
		logx.Infof("%s: %s of %s (%d%%)", p.label, humanSize(p.read), humanSize(p.total), p.read*100/p.total)
	}
	return n, err
}

// extractZstdTar extracts a zstd-compressed tar archive into destDir. Only
// regular files and directories are extracted; symlinks and hard links are
// skipped and path traversal outside destDir is rejected.
func extractZstdTar(src, destDir string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return fmt.Errorf("open zstd stream: %w", err)
	}
	defer zr.Close()

	root, err := os.OpenRoot(destDir)
	if err != nil {
		return err
	}
	defer root.Close()

	tr := tar.NewReader(zr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}
		name := filepath.Clean(hdr.Name)
		if !filepath.IsLocal(name) || filepath.IsAbs(name) {
			return fmt.Errorf("unsafe path in DB archive: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := root.Mkdir(name, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
		case tar.TypeReg:
			if dir := filepath.Dir(name); dir != "." {
				if err := root.MkdirAll(dir, 0o755); err != nil {
					return err
				}
			}
			out, err := root.Create(name)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		}
		// symlinks, hard links and special files are skipped (the DB
		// archive only ships regular files)
	}
}

// directActivate hydrates the extracted database (auto-migrates the schema
// and creates the missing indexes), records the import metadata (checksum,
// source URL and client version) and atomically swaps it into
// <dbRoot>/v6 — the same steps the curator performs on a downloaded DB.
func directActivate(dbRoot, srcDir, sourceURL string) error {
	logx.Infof("hydrating vulnerability database ...")
	if err := dbv6.Hydrater()(srcDir); err != nil {
		return fmt.Errorf("hydrate database: %w", err)
	}

	if _, err := dbv6.WriteImportMetadata(afero.NewOsFs(), srcDir, sourceURL); err != nil {
		return fmt.Errorf("write import metadata: %w", err)
	}

	finalDir := filepath.Join(dbRoot, strconv.Itoa(dbv6.ModelVersion))
	if err := os.MkdirAll(dbRoot, 0o700); err != nil {
		return fmt.Errorf("create db root dir %s: %w", dbRoot, err)
	}
	if _, err := os.Stat(finalDir); err == nil {
		if err := os.RemoveAll(finalDir); err != nil {
			return fmt.Errorf("remove previous database: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect previous database: %w", err)
	}
	if err := os.Rename(srcDir, finalDir); err != nil {
		return fmt.Errorf("activate downloaded database: %w", err)
	}
	return nil
}

// humanSize renders a byte count with a binary unit suffix.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
