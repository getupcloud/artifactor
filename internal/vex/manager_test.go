package vex

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testOpenVex = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/test",
  "author": "test",
  "timestamp": "2026-11-19T00:00:00Z",
  "version": 1,
  "statements": [
    {"@id": "s1", "status": "not_affected", "vulnerability": {"name": "CVE-2026-0001"}, "products": [{"@id": "pkg:generic/app@1.0"}]},
    {"@id": "s2", "status": "fixed", "vulnerability": {"name": "CVE-2026-0002"}, "products": [{"@id": "pkg:generic/app@1.0"}]},
    {"@id": "s3", "status": "not_affected", "vulnerability": {"name": "CVE-2026-0003"}, "products": [{"@id": "pkg:generic/app@1.0"}]}
  ]
}`

const testCSAF = `{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "publisher": {"category": "vendor", "name": "Test", "namespace": "https://example.com"},
    "title": "Test VEX advisory",
    "tracking": {
      "current_release_date": "2026-11-19T00:00:00Z",
      "id": "test-1",
      "initial_release_date": "2026-11-19T00:00:00Z",
      "revision_history": [{"date": "2026-11-19T00:00:00Z", "number": "1", "summary": "initial"}],
      "status": "final",
      "version": "1"
    }
  },
  "vulnerabilities": [{"cve": "CVE-2026-1111"}, {"cve": "CVE-2026-1111"}, {"cve": "CVE-2026-2222"}]
}`

func TestAddListRemove(t *testing.T) {
	m := New()

	info, err := m.Add("app.vex.json", []byte(testOpenVex))
	if err != nil {
		t.Fatalf("add openvex: %v", err)
	}
	if info.Format != "openvex" || info.Size != len(testOpenVex) || info.Records != 3 {
		t.Errorf("info = %+v", info)
	}
	if !strings.Contains(info.Summary, "3 statement(s)") || !strings.Contains(info.Summary, "2 not_affected") || !strings.Contains(info.Summary, "3 CVE(s)") {
		t.Errorf("summary = %q", info.Summary)
	}

	info, err = m.Add("csaf.json", []byte(testCSAF))
	if err != nil {
		t.Fatalf("add csaf: %v", err)
	}
	if info.Format != "csaf" || info.Records != 3 || !strings.Contains(info.Summary, "Test VEX advisory") || !strings.Contains(info.Summary, "2 CVE(s)") {
		t.Errorf("csaf info = %+v", info)
	}

	// duplicates and invalid formats are rejected
	if _, err := m.Add("app.vex.json", []byte(testOpenVex)); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate err = %v, want ErrDuplicate", err)
	}
	if _, err := m.Add("bad.txt", []byte("not a vex document")); err == nil {
		t.Error("invalid format accepted")
	}
	if _, err := m.Add("  ", []byte(testOpenVex)); err == nil {
		t.Error("empty name accepted")
	}

	// list keeps insertion order; content round-trips; docs carry the name
	list := m.List()
	if len(list) != 2 || list[0].Name != "app.vex.json" || list[1].Name != "csaf.json" {
		t.Fatalf("list = %+v", list)
	}
	content, err := m.Content("app.vex.json")
	if err != nil || string(content) != testOpenVex {
		t.Errorf("content = %q, %v", string(content), err)
	}
	docs := m.Docs()
	if len(docs) != 2 || docs[0].Name != "app.vex.json" || docs[0].Path == "" {
		t.Fatalf("docs = %+v", docs)
	}

	// remove forgets the entry
	if err := m.Remove("csaf.json"); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := m.Remove("csaf.json"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove again err = %v, want ErrNotFound", err)
	}
	if len(m.List()) != 1 || len(m.Docs()) != 1 {
		t.Errorf("list after remove = %+v", m.List())
	}
	if _, err := m.Content("csaf.json"); !errors.Is(err, ErrNotFound) {
		t.Errorf("content after remove err = %v", err)
	}
}

func TestInfoFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "startup.vex.json")
	if err := os.WriteFile(path, []byte(testOpenVex), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := InfoFromFile(path, "startup.vex.json")
	if err != nil {
		t.Fatalf("InfoFromFile: %v", err)
	}
	if info.Name != "startup.vex.json" || info.Format != "openvex" || info.Size != len(testOpenVex) || info.Records != 3 {
		t.Errorf("info = %+v", info)
	}
	if info.Removable {
		t.Error("startup doc marked removable")
	}
	if !strings.Contains(info.Summary, "3 statement(s)") {
		t.Errorf("summary = %q", info.Summary)
	}
	if _, err := InfoFromFile(filepath.Join(t.TempDir(), "missing.json"), "missing.json"); err == nil {
		t.Error("missing file accepted")
	}
}
