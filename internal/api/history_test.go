package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/getupcloud/artifactor/internal/clusters"
)

func TestSaveHistory(t *testing.T) {
	srv, store := testServer(t)
	srv.opts.HistoryDir = filepath.Join(t.TempDir(), "history")

	// no scan started yet → no-op
	srv.SaveHistory()
	if _, err := os.Stat(srv.opts.HistoryDir); !os.IsNotExist(err) {
		t.Fatal("SaveHistory wrote something without a scan")
	}

	if !store.TryStartScan(nil) {
		t.Fatal("TryStartScan rejected")
	}
	srv.SaveHistory()

	days, err := os.ReadDir(srv.opts.HistoryDir)
	if err != nil || len(days) != 1 {
		t.Fatalf("history days = %v (%v)", days, err)
	}
	times, err := os.ReadDir(filepath.Join(srv.opts.HistoryDir, days[0].Name()))
	if err != nil || len(times) != 1 {
		t.Fatalf("history times = %v (%v)", times, err)
	}
	dir := filepath.Join(srv.opts.HistoryDir, days[0].Name(), times[0].Name())

	summary, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatalf("summary.json: %v", err)
	}
	var entry HistoryEntry
	if err := json.Unmarshal(summary, &entry); err != nil {
		t.Fatalf("summary.json invalid: %v", err)
	}
	if entry.Total != 4 || entry.Critical != 1 || entry.High != 1 || entry.Medium != 2 {
		t.Errorf("summary counts = %+v, want total=4 critical=1 high=1 medium=2", entry)
	}
	if entry.Images != 3 {
		t.Errorf("summary images = %d, want 3", entry.Images)
	}
	if entry.Name != filepath.Join(days[0].Name(), times[0].Name()) {
		t.Errorf("summary name = %q", entry.Name)
	}

	scan, err := os.ReadFile(filepath.Join(dir, "scan.json"))
	if err != nil {
		t.Fatalf("scan.json: %v", err)
	}
	var snap map[string]any
	if err := json.Unmarshal(scan, &snap); err != nil {
		t.Fatalf("scan.json invalid: %v", err)
	}
	if cves, ok := snap["cves"].([]any); !ok || len(cves) != 4 {
		t.Errorf("scan.json cves = %v, want 4 rows", snap["cves"])
	}
}

func TestSaveHistoryClusterContext(t *testing.T) {
	srv, store := testServer(t)
	mgr := clusters.New()
	if err := mgr.AddStartup("default", "kubeconfig", nil, []byte(testKubeconfig), nil); err != nil {
		t.Fatal(err)
	}
	srv.opts.Clusters = mgr
	srv.opts.HistoryDir = filepath.Join(t.TempDir(), "history")

	if !store.TryStartScan(nil) {
		t.Fatal("TryStartScan rejected")
	}
	srv.SaveHistory()

	days, err := os.ReadDir(srv.opts.HistoryDir)
	if err != nil || len(days) != 1 {
		t.Fatalf("history days = %v (%v)", days, err)
	}
	times, err := os.ReadDir(filepath.Join(srv.opts.HistoryDir, days[0].Name()))
	if err != nil || len(times) != 1 {
		t.Fatalf("history times = %v (%v)", times, err)
	}
	summary, err := os.ReadFile(filepath.Join(srv.opts.HistoryDir, days[0].Name(), times[0].Name(), "summary.json"))
	if err != nil {
		t.Fatalf("summary.json: %v", err)
	}
	var entry HistoryEntry
	if err := json.Unmarshal(summary, &entry); err != nil {
		t.Fatalf("summary.json invalid: %v", err)
	}
	if entry.Cluster != "default" {
		t.Errorf("summary cluster = %q, want default", entry.Cluster)
	}
	if entry.Context != "ctx-beta" {
		t.Errorf("summary context = %q, want ctx-beta", entry.Context)
	}
}

func TestHistoryEndpoints(t *testing.T) {
	srv, store := testServer(t)
	h := srv.Handler()

	// disabled → empty list and the status payload hides the SPA section
	rec, out := doJSON(t, h, http.MethodGet, "/api/history", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("history list -> %d: %s", rec.Code, rec.Body.String())
	}
	if entries, _ := out["entries"].([]any); len(entries) != 0 {
		t.Errorf("disabled history entries = %v, want none", out["entries"])
	}
	rec, out = doJSON(t, h, http.MethodGet, "/api/status", nil)
	if out["history"] != false {
		t.Errorf("status.history = %v, want false while disabled", out["history"])
	}

	srv.opts.HistoryDir = t.TempDir()
	rec, out = doJSON(t, h, http.MethodGet, "/api/status", nil)
	if out["history"] != true {
		t.Errorf("status.history = %v, want true once enabled", out["history"])
	}
	if !store.TryStartScan(nil) {
		t.Fatal("TryStartScan rejected")
	}
	srv.SaveHistory()

	rec, out = doJSON(t, h, http.MethodGet, "/api/history", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("history list -> %d: %s", rec.Code, rec.Body.String())
	}
	entries, _ := out["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("history entries = %v, want 1", out["entries"])
	}
	name, _ := entries[0].(map[string]any)["name"].(string)
	if name == "" {
		t.Fatalf("history entry without name: %v", entries[0])
	}

	// get the saved scan
	rec, _ = doJSON(t, h, http.MethodGet, "/api/history/"+name, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("history get -> %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "CVE-2024-0001") {
		t.Errorf("history get body = %s", rec.Body.String())
	}

	// unknown name → 404
	rec, _ = doJSON(t, h, http.MethodGet, "/api/history/9999-99-99/00-00-00", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown history -> %d, want 404", rec.Code)
	}

	// path traversal → 404
	rec, _ = doJSON(t, h, http.MethodGet, "/api/history/..%2F..%2Fetc", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("traversal history -> %d, want 404", rec.Code)
	}
}
