package scanner

import (
	"fmt"
	"time"

	"github.com/getupcloud/artifactor/internal/logx"
)

// ScanStats aggregates the metrics of the last scan run: total time,
// average time per image, bytes received and average download speed.
type ScanStats struct {
	Images       int     `json:"images"`
	DurationSec  float64 `json:"durationSec"`
	AvgSecPerImg float64 `json:"avgSecPerImage"`
	Bytes        int64   `json:"bytesReceived"`
	BytesPerSec  float64 `json:"bytesPerSec"`
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
