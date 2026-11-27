package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/getupcloud/artifactor/internal/logx"
)

// HistoryEntry is the summary of one saved scan, shown in the history list
// and chart of the SPA.
type HistoryEntry struct {
	Name        string    `json:"name"`
	StartedAt   time.Time `json:"startedAt"`
	DurationSec float64   `json:"durationSec,omitempty"`
	Images      int       `json:"images"`
	Total       int       `json:"total"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
	Negligible  int       `json:"negligible"`
	Unknown     int       `json:"unknown"`
	// Cluster and Context identify the cluster the scan ran against
	// (empty when there is no cluster registry, e.g. --from-sbom).
	Cluster string `json:"cluster,omitempty"`
	Context string `json:"context,omitempty"`
}

// SaveHistory persists the current scan results under HistoryDir as
// <day>/<hh-mm-ss> of the scan start, writing a summary.json (counts per
// severity, used by the list/chart) and the full snapshot (scan.json, the
// same shape the SPA loads as a snapshot). It is a no-op when HistoryDir is
// empty; failures are logged and never fail the scan.
func (s *Server) SaveHistory() {
	if s.opts.HistoryDir == "" {
		return
	}
	started := s.opts.Store.ScanStartedAt()
	if started == nil {
		return
	}
	snap := s.buildSnapshot()

	name := started.Format("2006-01-02/15-04-05")
	dir := filepath.Join(s.opts.HistoryDir, name)
	for i := 2; ; i++ {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			break
		}
		dir = filepath.Join(s.opts.HistoryDir, fmt.Sprintf("%s-%d", name, i))
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logx.Warnf("save scan history: create dir %s: %v", dir, err)
		return
	}

	entry := HistoryEntry{
		StartedAt: *started,
		Images:    len(snap.Images),
		Total:     len(snap.Cves),
	}
	if rel, err := filepath.Rel(s.opts.HistoryDir, dir); err == nil {
		entry.Name = rel
	}
	if s.opts.Clusters != nil {
		entry.Cluster = s.opts.Clusters.SelectedName()
		if sel := s.opts.Clusters.Selected(); sel != nil {
			entry.Context = sel.CurrentContext
		}
	}
	for _, c := range snap.Cves {
		switch strings.ToLower(c.Severity) {
		case "critical":
			entry.Critical++
		case "high":
			entry.High++
		case "medium":
			entry.Medium++
		case "low":
			entry.Low++
		case "negligible":
			entry.Negligible++
		default:
			entry.Unknown++
		}
	}
	entry.DurationSec = time.Since(*started).Round(time.Millisecond).Seconds()

	if err := writeHistoryJSON(filepath.Join(dir, "summary.json"), entry); err != nil {
		logx.Warnf("save scan history: %v", err)
		return
	}
	if err := writeHistoryJSON(filepath.Join(dir, "scan.json"), snap); err != nil {
		logx.Warnf("save scan history: %v", err)
		return
	}
	logx.Infof("scan history saved to %s (%d images, %d CVE(s))", dir, len(snap.Images), len(snap.Cves))
}

// writeHistoryJSON writes v as indented JSON to path (readable files on the
// pod, easy to debug).
func writeHistoryJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	return os.WriteFile(path, data, 0o644)
}

// historyEntryNames returns the relative paths (day/time) of the saved
// scans, newest first.
func (s *Server) historyEntryNames() []string {
	days, err := os.ReadDir(s.opts.HistoryDir)
	if err != nil {
		return nil
	}
	names := []string{}
	for _, day := range days {
		if !day.IsDir() {
			continue
		}
		times, err := os.ReadDir(filepath.Join(s.opts.HistoryDir, day.Name()))
		if err != nil {
			continue
		}
		for _, t := range times {
			if !t.IsDir() {
				continue
			}
			name := filepath.Join(day.Name(), t.Name())
			names = append(names, name)
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names
}

// GET /api/history returns the saved scans (newest first) with their
// severity counts; empty (not an error) when history is disabled.
func (s *Server) handleHistoryList(w http.ResponseWriter, r *http.Request) {
	entries := []HistoryEntry{}
	if s.opts.HistoryDir != "" {
		for _, name := range s.historyEntryNames() {
			entry, err := readHistorySummary(s.opts.HistoryDir, name)
			if err != nil {
				logx.Warnf("scan history entry %s: %v", name, err)
				continue
			}
			entries = append(entries, entry)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// readHistorySummary reads the summary.json of one history entry.
func readHistorySummary(root, name string) (HistoryEntry, error) {
	data, err := os.ReadFile(filepath.Join(root, name, "summary.json"))
	if err != nil {
		return HistoryEntry{}, err
	}
	var entry HistoryEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return HistoryEntry{}, fmt.Errorf("invalid summary: %w", err)
	}
	return entry, nil
}

// GET /api/history/{name...} returns the full snapshot (scan.json) of one
// saved scan. The name is confined to the history directory (404 for
// unknown names or path traversal attempts).
func (s *Server) handleHistoryGet(w http.ResponseWriter, r *http.Request) {
	if s.opts.HistoryDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "scan history is disabled"})
		return
	}
	name := r.PathValue("name")
	dir, ok := s.historyDirFor(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown scan"})
		return
	}
	data, err := os.ReadFile(filepath.Join(dir, "scan.json"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown scan"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// historyDirFor resolves a history entry name to its directory, confined to
// HistoryDir. ok is false for unknown or unsafe names.
func (s *Server) historyDirFor(name string) (string, bool) {
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	dir := filepath.Join(s.opts.HistoryDir, clean)
	if !strings.HasPrefix(dir, s.opts.HistoryDir+string(os.PathSeparator)) {
		return "", false
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return "", false
	}
	return dir, true
}
