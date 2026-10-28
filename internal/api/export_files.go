// File exporters for the one-shot CLI mode: per-image syft SBOM (syft-json)
// and grype-style JSON reports.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/getupcloud/artifactor/internal/scanner"
)

var unsafeFileNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// imageFileName turns an image reference into a safe file name component.
func imageFileName(image string) string {
	return unsafeFileNameChars.ReplaceAllString(image, "_")
}

// grypeReport mirrors the structure of grype's JSON output for a single
// image scan.
type grypeReport struct {
	Matches    []grypeMatch    `json:"matches"`
	Source     grypeSource     `json:"source"`
	Distro     grypeDistro     `json:"distro,omitempty"`
	Descriptor grypeDescriptor `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
	MatchDetails  []grypeMatchDetail `json:"matchDetails"`
}

type grypeVulnerability struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:"urls,omitempty"`
	DataSource  string   `json:"dataSource,omitempty"`
	Fix         grypeFix `json:"fix"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeArtifact struct {
	Name      string   `json:"name"`
	Version   string   `json:"version"`
	Type      string   `json:"type"`
	PURL      string   `json:"purl,omitempty"`
	Locations []string `json:"locations,omitempty"`
}

type grypeMatchDetail struct {
	Type    string `json:"type"`
	Matcher string `json:"matcher"`
}

type grypeSource struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type grypeDistro struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type grypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// buildGrypeReport converts the stored CVE matches of one image into a
// grype-shaped JSON report.
func (s *Server) buildGrypeReport(image string, res scanner.Result) grypeReport {
	report := grypeReport{
		Source: grypeSource{Type: "image", Target: image},
		Descriptor: grypeDescriptor{
			Name:    "artifactor",
			Version: "dev",
		},
	}
	if res.Distro != "" {
		name, version, _ := strings.Cut(res.Distro, " ")
		report.Distro = grypeDistro{Name: name, Version: version}
	}
	for _, c := range res.Cves {
		fix := grypeFix{Versions: c.FixedIn}
		if len(c.FixedIn) > 0 {
			fix.State = "fixed"
		} else {
			fix.State = "not-fixed"
		}
		report.Matches = append(report.Matches, grypeMatch{
			Vulnerability: grypeVulnerability{
				ID:          c.ID,
				Severity:    c.Severity,
				Description: c.Description,
				URLs:        c.URLs,
				DataSource:  c.DataSource,
				Fix:         fix,
			},
			Artifact: grypeArtifact{
				Name:    c.PackageName,
				Version: c.PackageVersion,
				Type:    c.PackageType,
			},
			MatchDetails: []grypeMatchDetail{{Matcher: c.Matcher}},
		})
	}
	return report
}

// ExportCVEsCSV writes the full CVE report (unfiltered) as CSV to path.
func (s *Server) ExportCVEsCSV(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return writeCVEsCSV(f, s.filteredCVEs(url.Values{}))
}

// ExportSBOMs writes one syft-json SBOM file per scanned image into dir.
func (s *Server) ExportSBOMs(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	written := 0
	for _, res := range s.opts.Store.Snapshot("") {
		if res.Status != scanner.StatusScanned || len(res.SBOM) == 0 {
			continue
		}
		data, err := prettyJSON(res.SBOM)
		if err != nil {
			return written, fmt.Errorf("invalid SBOM JSON for %s: %w", res.Image, err)
		}
		path := filepath.Join(dir, imageFileName(res.Image)+".sbom.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// prettyJSON validates that data is well-formed JSON and returns it indented
// with two spaces per level, so exported scan files are readable and never
// contain malformed JSON.
func prettyJSON(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, data, "", "  "); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ExportGrype writes one grype-shaped JSON report per scanned image into dir.
func (s *Server) ExportGrype(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}
	written := 0
	for _, res := range s.opts.Store.Snapshot("") {
		if res.Status != scanner.StatusScanned {
			continue
		}
		data, err := json.MarshalIndent(s.buildGrypeReport(res.Image, res), "", "  ")
		if err != nil {
			return written, fmt.Errorf("encode grype report for %s: %w", res.Image, err)
		}
		path := filepath.Join(dir, imageFileName(res.Image)+".grype.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return written, err
		}
		written++
	}
	return written, nil
}

// ExportAll writes the complete export into dir: the self-contained HTML
// report plus the per-image SBOM and grype JSON files.
func (s *Server) ExportAll(dir string) (htmlPath, csvPath string, sbomCount, grypeCount int, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", 0, 0, err
	}
	htmlPath = filepath.Join(dir, "scan.html")
	if err := os.WriteFile(htmlPath, s.ExportHTML(), 0o644); err != nil {
		return "", "", 0, 0, err
	}
	csvPath = filepath.Join(dir, "scan.csv")
	if err := s.ExportCVEsCSV(csvPath); err != nil {
		return "", "", 0, 0, err
	}
	if sbomCount, err = s.ExportSBOMs(filepath.Join(dir, "sbom")); err != nil {
		return "", "", 0, 0, err
	}
	if grypeCount, err = s.ExportGrype(filepath.Join(dir, "grype")); err != nil {
		return "", "", 0, 0, err
	}
	return htmlPath, csvPath, sbomCount, grypeCount, nil
}
