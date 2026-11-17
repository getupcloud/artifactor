// Package selfupdate checks the latest GitHub release of artifactor and, on
// request, replaces the running binary with the release asset built for the
// current platform. Everything is plain net/http + stdlib tar/gzip; errors
// are returned to the caller (main logs them via logx).
package selfupdate

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Masterminds/semver/v3"
)

const (
	// latestReleaseURL is the GitHub API endpoint for the latest release.
	latestReleaseURL = "https://api.github.com/repos/getupcloud/artifactor/releases/latest"
	// binaryName is the name of the binary inside the release archive.
	binaryName = "artifactor"
)

// Release is the subset of a GitHub release needed by the self-update flow.
type Release struct {
	Version   string // tag name without the leading "v"
	AssetName string // archive file name, e.g. artifactor_linux_amd64.tar.gz
	AssetURL  string // download URL of the archive
}

// ghRelease and ghAsset mirror the relevant fields of the GitHub releases
// API response.
type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// AssetName returns the archive name GoReleaser generates for a platform.
func AssetName(goos, goarch string) string {
	return fmt.Sprintf("%s_%s_%s.tar.gz", binaryName, goos, goarch)
}

// IsNewer reports whether latest is a strictly newer semver than current.
// A leading "v" on either version is ignored.
func IsNewer(current, latest string) (bool, error) {
	c, err := semver.NewVersion(strings.TrimPrefix(current, "v"))
	if err != nil {
		return false, fmt.Errorf("current version %q is not valid semver: %w", current, err)
	}
	l, err := semver.NewVersion(strings.TrimPrefix(latest, "v"))
	if err != nil {
		return false, fmt.Errorf("latest version %q is not valid semver: %w", latest, err)
	}
	return l.GreaterThan(c), nil
}

// LatestRelease fetches the latest GitHub release and returns it together
// with the archive asset for the current platform. The metadata request has
// a 5s timeout: an unreachable GitHub must not delay the program for long.
func LatestRelease(ctx context.Context, insecure bool) (*Release, error) {
	client := httpClient(insecure)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestReleaseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "artifactor")
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, fmt.Errorf("read release metadata: %w", err)
	}
	return parseRelease(data, runtime.GOOS, runtime.GOARCH)
}

// parseRelease decodes the GitHub releases API JSON and selects the archive
// asset matching the given platform.
func parseRelease(data []byte, goos, goarch string) (*Release, error) {
	var rel ghRelease
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("decode release metadata: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("release metadata has no tag_name")
	}
	want := AssetName(goos, goarch)
	for _, a := range rel.Assets {
		if a.Name == want && a.BrowserDownloadURL != "" {
			return &Release{
				Version:   strings.TrimPrefix(rel.TagName, "v"),
				AssetName: a.Name,
				AssetURL:  a.BrowserDownloadURL,
			}, nil
		}
	}
	return nil, fmt.Errorf("release %s has no %s asset", rel.TagName, want)
}

// Apply downloads the release archive, extracts only the artifactor binary
// and replaces the file at target (symlinks resolved). The replacement is
// atomic (temp file in the same directory + rename). When the target
// directory is not writable, the binary is staged in the system temp dir and
// installed with "sudo install" (the sudo password prompt runs on the
// terminal).
func (r *Release) Apply(ctx context.Context, target string, insecure bool) error {
	if target == "" {
		return errors.New("empty target path")
	}
	dest, err := filepath.EvalSymlinks(target)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", target, err)
	}

	client := httpClient(insecure)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.AssetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "artifactor")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", r.AssetURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: server returned %s", r.AssetURL, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("open %s: %w", r.AssetName, err)
	}
	defer gz.Close()

	writable := dirWritable(filepath.Dir(dest))
	out, err := stagingFile(dest, writable)
	if err != nil {
		return err
	}
	outPath := out.Name()
	defer os.Remove(outPath)

	if err := extractBinary(tar.NewReader(gz), out); err != nil {
		out.Close()
		return err
	}
	if err := out.Chmod(0o755); err != nil {
		out.Close()
		return fmt.Errorf("chmod %s: %w", outPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}

	if writable {
		if err := os.Rename(outPath, dest); err != nil {
			return fmt.Errorf("replace %s: %w", dest, err)
		}
		return nil
	}
	cmd := exec.Command("sudo", "install", "-m", "0755", outPath, dest)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return errors.New("no write permission for the binary directory and sudo was not found in PATH")
		}
		return fmt.Errorf("sudo install: %w", err)
	}
	return nil
}

// extractBinary streams the single "artifactor" entry of the archive into
// out. Only a top-level regular file with exactly that name is accepted
// (which also rules out path traversal entries).
func extractBinary(tr *tar.Reader, out io.Writer) error {
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("archive has no %s entry", binaryName)
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Name != binaryName {
			continue
		}
		if _, err := io.Copy(out, tr); err != nil {
			return fmt.Errorf("extract %s: %w", binaryName, err)
		}
		return nil
	}
}

// stagingFile opens the temp file that receives the extracted binary: in the
// destination directory when it is writable (so the final rename stays on
// the same filesystem), otherwise in the system temp dir.
func stagingFile(dest string, writable bool) (*os.File, error) {
	if writable {
		f, err := os.OpenFile(dest+".new", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
		if err != nil {
			return nil, fmt.Errorf("create %s.new: %w", dest, err)
		}
		return f, nil
	}
	f, err := os.CreateTemp("", "artifactor-update-*")
	if err != nil {
		return nil, fmt.Errorf("create staging file: %w", err)
	}
	return f, nil
}

// dirWritable reports whether files can be created in dir.
func dirWritable(dir string) bool {
	probe, err := os.CreateTemp(dir, ".artifactor-write-probe-*")
	if err != nil {
		return false
	}
	name := probe.Name()
	probe.Close()
	os.Remove(name)
	return true
}

// httpClient builds a client honoring --insecure-skip-tls, with the same
// conservative timeouts used by the direct DB downloader.
func httpClient(insecure bool) *http.Client {
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &http.Client{Transport: tr}
}
