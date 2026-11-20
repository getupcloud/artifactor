// Package vex keeps the OpenVEX/CSAF documents uploaded via the web UI in
// memory (plus one temp file each, so the grype VEX processor can read
// them) and summarizes them for the UI dialog. Like the cluster
// kubeconfigs, the contents never leave the process except through the
// explicit download endpoint.
package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	grypevex "github.com/anchore/grype/grype/vex"

	"github.com/getupcloud/artifactor/internal/scanner"
)

// ErrDuplicate is returned by Add when the file name already exists.
var ErrDuplicate = errors.New("a VEX file with this name already exists")

// ErrNotFound is returned when a file name is unknown.
var ErrNotFound = errors.New("VEX file not found")

// Info is the API-facing projection of a VEX document (summary metadata
// only — the content is served by the download endpoint).
type Info struct {
	Name      string `json:"name"`
	Size      int    `json:"size"`
	Format    string `json:"format"`    // "openvex" or "csaf"
	Summary   string `json:"summary"`   // one-line human summary
	Records   int    `json:"records"`   // statements (OpenVEX) or vulnerabilities (CSAF)
	Removable bool   `json:"removable"` // false for startup --vex documents (can't be removed via the UI)
}

type file struct {
	info Info
	path string // temp file path the grype processor reads
}

// Manager is the in-memory registry of uploaded VEX documents.
type Manager struct {
	mu    sync.Mutex
	order []string
	files map[string]*file
	dir   string // temp dir holding the uploaded contents (created lazily)
}

// New returns an empty VEX upload registry.
func New() *Manager {
	return &Manager{files: map[string]*file{}}
}

// Add registers an uploaded VEX document: validates the format (OpenVEX or
// CSAF, via the grype processor — the same check as ResolveVexFiles),
// stores the content in memory and writes a temp copy the processor can
// read. The name is used for display and per-CVE attribution; only its
// base name is used for the temp file.
func (m *Manager) Add(name string, content []byte) (Info, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	name = strings.TrimSpace(name)
	if name == "" {
		return Info{}, errors.New("name is required")
	}
	if _, ok := m.files[name]; ok {
		return Info{}, ErrDuplicate
	}
	if m.dir == "" {
		dir, err := os.MkdirTemp("", "artifactor-vex-*")
		if err != nil {
			return Info{}, fmt.Errorf("create temp dir: %w", err)
		}
		m.dir = dir
	}
	path := filepath.Join(m.dir, filepath.Base(name))
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return Info{}, fmt.Errorf("write temp file: %w", err)
	}
	if _, err := grypevex.NewProcessor(grypevex.ProcessorOptions{Documents: []string{path}}); err != nil {
		_ = os.Remove(path)
		return Info{}, fmt.Errorf("unsupported VEX document: %w", err)
	}
	format, summary, records, err := summarize(content)
	if err != nil {
		_ = os.Remove(path)
		return Info{}, fmt.Errorf("unsupported VEX document: %w", err)
	}
	info := Info{Name: name, Size: len(content), Format: format, Summary: summary, Records: records, Removable: true}
	m.files[name] = &file{info: info, path: path}
	m.order = append(m.order, name)
	return info, nil
}

// InfoFromFile reads a VEX document from a local file and builds its Info
// projection (used for the startup --vex documents, which are not uploaded
// through Add and cannot be removed via the UI).
func InfoFromFile(path, name string) (Info, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Info{}, err
	}
	format, summary, records, err := summarize(content)
	if err != nil {
		return Info{}, err
	}
	return Info{Name: name, Size: len(content), Format: format, Summary: summary, Records: records}, nil
}

// Remove unregisters an uploaded document and deletes its temp file.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[name]
	if !ok {
		return ErrNotFound
	}
	delete(m.files, name)
	for i, n := range m.order {
		if n == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	if f.path != "" {
		_ = os.Remove(f.path)
	}
	return nil
}

// List returns the uploaded documents in insertion order.
func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(m.order))
	for _, name := range m.order {
		if f, ok := m.files[name]; ok {
			out = append(out, f.info)
		}
	}
	return out
}

// Content returns the raw contents of an uploaded document.
func (m *Manager) Content(name string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f, ok := m.files[name]
	if !ok {
		return nil, ErrNotFound
	}
	return f.content(), nil
}

func (f *file) content() []byte {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return nil
	}
	return data
}

// Docs returns the uploaded documents as scanner.VexDoc entries (temp path
// for the processor + upload name for the per-CVE attribution).
func (m *Manager) Docs() []scanner.VexDoc {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]scanner.VexDoc, 0, len(m.order))
	for _, name := range m.order {
		if f, ok := m.files[name]; ok {
			out = append(out, scanner.VexDoc{Path: f.path, Name: f.info.Name})
		}
	}
	return out
}

// summarize detects the document format from the JSON shape and builds the
// one-line human summary shown in the UI dialog, plus the record count
// (statements for OpenVEX, vulnerabilities for CSAF).
func summarize(content []byte) (format, summary string, records int, err error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return "", "", 0, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, ok := raw["statements"]; ok {
		summary, records, err := summarizeOpenVex(content)
		return "openvex", summary, records, err
	}
	if _, ok := raw["document"]; ok {
		summary, records, err := summarizeCSAF(content)
		return "csaf", summary, records, err
	}
	return "", "", 0, errors.New("not an OpenVEX or CSAF document")
}

// summarizeOpenVex builds "N statement(s) · X not_affected · Y fixed · M CVE(s)".
func summarizeOpenVex(content []byte) (string, int, error) {
	var doc struct {
		Statements []struct {
			Status        string `json:"status"`
			Vulnerability struct {
				Name string `json:"name"`
			} `json:"vulnerability"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return "", 0, fmt.Errorf("not valid JSON: %w", err)
	}
	statuses := map[string]int{}
	cves := map[string]struct{}{}
	for _, st := range doc.Statements {
		statuses[st.Status]++
		if st.Vulnerability.Name != "" {
			cves[st.Vulnerability.Name] = struct{}{}
		}
	}
	keys := make([]string, 0, len(statuses))
	for k := range statuses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := []string{fmt.Sprintf("%d statement(s)", len(doc.Statements))}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", statuses[k], k))
	}
	parts = append(parts, fmt.Sprintf("%d CVE(s)", len(cves)))
	return strings.Join(parts, " · "), len(doc.Statements), nil
}

// summarizeCSAF builds `"<title>" — N vuln(s) · M CVE(s)`.
func summarizeCSAF(content []byte) (string, int, error) {
	var doc struct {
		Document struct {
			Title string `json:"title"`
		} `json:"document"`
		Vulnerabilities []struct {
			CVE string `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(content, &doc); err != nil {
		return "", 0, fmt.Errorf("not valid JSON: %w", err)
	}
	cves := map[string]struct{}{}
	for _, v := range doc.Vulnerabilities {
		if v.CVE != "" {
			cves[v.CVE] = struct{}{}
		}
	}
	title := doc.Document.Title
	if title == "" {
		title = "(untitled)"
	}
	return fmt.Sprintf("%q — %d vuln(s) · %d CVE(s)", title, len(doc.Vulnerabilities), len(cves)), len(doc.Vulnerabilities), nil
}
