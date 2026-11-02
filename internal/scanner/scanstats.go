package scanner

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/getupcloud/artifactor/internal/logx"
	"github.com/getupcloud/artifactor/internal/registryauth"
)

// ScanStats aggregates the metrics of the last scan run: total time,
// average time per image, bytes received and average download speed.
type ScanStats struct {
	Images       int     `json:"images"`
	DurationSec  float64 `json:"durationSec"`
	AvgSecPerImg float64 `json:"avgSecPerImage"`
	Bytes        int64   `json:"bytesReceived"`
	BytesPerSec  float64 `json:"bytesPerSec"`
	// Registries carries the access results per container registry:
	// attempted images, access failures (syft/pull phase) and the error rate.
	Registries []RegistryStats `json:"registries,omitempty"`
}

// RegistryStats aggregates the access results of one container registry
// during the last scan run.
type RegistryStats struct {
	Registry  string  `json:"registry"`
	Total     int     `json:"total"`     // images attempted from this registry
	Errors    int     `json:"errors"`    // registry access failures (syft phase)
	ErrorRate float64 `json:"errorRate"` // Errors / Total
}

// finishScanStats computes and stores the scan metrics, and logs them.
// images is the number of successfully scanned images, bytes the total
// amount of data received from the registries.
func (s *Scanner) finishScanStats(start time.Time, images, bytes int64) {
	d := time.Since(start)
	stats := ScanStats{
		Images:      int(images),
		DurationSec: d.Seconds(),
		Bytes:       bytes,
		Registries:  s.registryStats(),
	}
	if images > 0 {
		stats.AvgSecPerImg = d.Seconds() / float64(images)
	}
	if d.Seconds() > 0 {
		stats.BytesPerSec = float64(bytes) / d.Seconds()
	}
	s.opts.Store.SetStats(stats)
	logx.Infof("scan finished: %d image(s) in %s (avg %s/image), %s received (avg %s/s)",
		stats.Images,
		d.Round(time.Second),
		(time.Duration(stats.AvgSecPerImg * float64(time.Second))).Round(10*time.Millisecond),
		formatBytes(stats.Bytes),
		formatBytes(int64(stats.BytesPerSec)))
	for _, rs := range stats.Registries {
		if rs.Errors > 0 {
			logx.Warnf("registry %s: %d/%d access error(s) (%.0f%%)", rs.Registry, rs.Errors, rs.Total, rs.ErrorRate*100)
		} else {
			logx.Infof("registry %s: %d/%d access error(s)", rs.Registry, rs.Errors, rs.Total)
		}
	}
}

// registryStats aggregates per-registry access results from the store:
// images attempted (scanned or failed) per registry authority and the
// access error rate (failures in the syft/pull phase; grype/DB failures do
// not count as registry access errors). Skipped for --from-sbom runs, which
// never touch a registry.
func (s *Scanner) registryStats() []RegistryStats {
	if s.opts.FromSBOM != "" {
		return nil
	}
	byRegistry := map[string]*RegistryStats{}
	for _, r := range s.opts.Store.Summaries() {
		if r.Status != StatusScanned && r.Status != StatusError {
			continue // not attempted in this run
		}
		registry := registryauth.AuthorityForImage(r.Image)
		if registry == "" {
			continue
		}
		rs := byRegistry[registry]
		if rs == nil {
			rs = &RegistryStats{Registry: registry}
			byRegistry[registry] = rs
		}
		rs.Total++
		if r.Status == StatusError && strings.HasPrefix(r.Error, "syft: ") {
			rs.Errors++
		}
	}
	out := make([]RegistryStats, 0, len(byRegistry))
	for _, rs := range byRegistry {
		rs.ErrorRate = float64(rs.Errors) / float64(rs.Total)
		out = append(out, *rs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Errors != out[j].Errors {
			return out[i].Errors > out[j].Errors
		}
		return out[i].Registry < out[j].Registry
	})
	return out
}

// formatBytes renders a byte count with binary (KiB/MiB/GiB) units.
func formatBytes(n int64) string {
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
