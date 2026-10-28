// Package api exposes the scan results as a small JSON API and serves the
// single-page application. It can also render the SPA as a single
// self-contained HTML file with the current results embedded.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/scanner"
)

// exportMarker is replaced with the embedded data snapshot when exporting.
const exportMarker = "<!-- EXPORT_DATA -->"

// namedVuln is a well-known vulnerability family (from web/names.json in
// the repository).
type namedVuln struct {
	Name string   `json:"name"`
	CVEs []string `json:"cves"`
}

// defaultNamesURL is the GitHub raw URL of the named vulnerabilities list;
// the process refreshes it at startup and falls back to the embedded copy.
const (
	defaultNamesURL       = "https://raw.githubusercontent.com/getupcloud/artifactor/main/web/names.json"
	namesFetchTimeout     = 10 * time.Second
	namesFetchMaxBodySize = 1 << 20 // 1 MiB
)

// Options wires the API server to the scan store and scan trigger.
type Options struct {
	Store     *scanner.Store
	Scanner   *scanner.Scanner
	SPA       []byte
	NamesJSON []byte // embedded contents of web/names.json (fallback list)
	NamesURL  string // override for the GitHub fetch (defaults to defaultNamesURL; mainly for tests)
	Mode      string // "in-cluster" or "kubeconfig"
	// Optional context shown in the report title and status payload.
	CustomerName string
	ClusterName  string
	K8sErr       error
	DB           func() scanner.DBStatus // dynamic DB status (DB initializes in the background)
}

// Server implements the HTTP API.
type Server struct {
	opts       Options
	namedMu    sync.RWMutex
	namedVulns []namedVuln
}

func New(opts Options) *Server {
	s := &Server{opts: opts}
	if err := json.Unmarshal(opts.NamesJSON, &s.namedVulns); err != nil || len(s.namedVulns) == 0 {
		s.namedVulns = []namedVuln{}
	}
	return s
}

// FetchNamedVulns refreshes the named vulnerability list from the GitHub
// repository with a 10 second timeout. On any failure the embedded copy
// stays in place and the error is returned for logging.
func (s *Server) FetchNamedVulns(ctx context.Context) error {
	url := s.opts.NamesURL
	if url == "" {
		url = defaultNamesURL
	}
	log.Printf("downloading named vulnerabilities list from %s ...", url)
	ctx, cancel := context.WithTimeout(ctx, namesFetchTimeout)
	defer cancel()
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, namesFetchMaxBodySize))
	if err != nil {
		return err
	}
	var groups []namedVuln
	if err := json.Unmarshal(data, &groups); err != nil || len(groups) == 0 {
		return fmt.Errorf("invalid names.json payload")
	}
	s.namedMu.Lock()
	s.namedVulns = groups
	s.namedMu.Unlock()
	log.Printf("named vulnerabilities list downloaded: %d bytes, %d entrie(s) in %s", len(data), len(groups), time.Since(start).Round(time.Millisecond))
	return nil
}

// namedVulnList returns the current named vulnerability groups.
func (s *Server) namedVulnList() []namedVuln {
	s.namedMu.RLock()
	defer s.namedMu.RUnlock()
	return s.namedVulns
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("GET /api/images", s.handleImages)
	mux.HandleFunc("GET /api/cves", s.handleCVEs)
	mux.HandleFunc("GET /api/named-vulns", s.handleNamedVulns)
	mux.HandleFunc("GET /api/namespaces", s.handleNamespaces)
	mux.HandleFunc("GET /api/artifacts", s.handleArtifacts)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("POST /api/scan", s.handleScan)
	mux.HandleFunc("GET /", s.handleSPA)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"ok": "true"})
}

func (s *Server) handleSPA(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(s.opts.SPA)
}

func (s *Server) statusPayload() map[string]any {
	db := s.opts.DB()
	if storeErr := s.opts.Store.DBError(); storeErr != "" {
		db.Error = storeErr
	}
	return map[string]any{
		"mode":         s.opts.Mode,
		"k8sError":     errString(s.opts.K8sErr),
		"scanning":     s.opts.Store.IsScanning(),
		"lastScanDone": s.opts.Store.LastScanDone(),
		"customer":     s.opts.CustomerName,
		"cluster":      s.opts.ClusterName,
		"db":           db,
	}
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.statusPayload())
}

func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.opts.Store.Summaries())
}

type imageRef struct {
	Image      string `json:"image"`
	Namespace  string `json:"namespace,omitempty"`
	Controller string `json:"controller,omitempty"`
}

type cveOut struct {
	Image  string     `json:"image"`
	Images []imageRef `json:"images"`
	scanner.CVE
}

// cveRows returns every CVE across scanned images, each with the full list
// of images (and workloads) containing it, ordered by severity desc, package
// name, CVE id.
func (s *Server) cveRows() []cveOut {
	// Index every CVE across all scanned images so each row can report the
	// full list of images containing it (used by the SPA's expandable rows).
	cveImages := map[string]map[string]struct{}{}
	imageInstances := map[string][]k8s.Instance{}
	for _, res := range s.opts.Store.Snapshot("") {
		if res.Status != scanner.StatusScanned {
			continue
		}
		imageInstances[res.Image] = res.Instances
		for _, c := range res.Cves {
			if cveImages[c.ID] == nil {
				cveImages[c.ID] = map[string]struct{}{}
			}
			cveImages[c.ID][res.Image] = struct{}{}
		}
	}

	out := []cveOut{}
	for _, res := range s.opts.Store.Snapshot("") {
		if res.Status != scanner.StatusScanned {
			continue
		}
		for _, c := range res.Cves {
			images := []imageRef{}
			for img := range cveImages[c.ID] {
				if insts, ok := imageInstances[img]; ok && len(insts) > 0 {
					for _, inst := range insts {
						images = append(images, imageRef{Image: img, Namespace: inst.Namespace, Controller: inst.Controller})
					}
				} else {
					images = append(images, imageRef{Image: img})
				}
			}
			sort.Slice(images, func(i, j int) bool {
				if images[i].Image != images[j].Image {
					return images[i].Image < images[j].Image
				}
				if images[i].Namespace != images[j].Namespace {
					return images[i].Namespace < images[j].Namespace
				}
				return images[i].Controller < images[j].Controller
			})
			out = append(out, cveOut{Image: res.Image, CVE: c, Images: images})
		}
	}

	rank := map[string]int{}
	for i, sev := range scanner.SeverityOrder {
		rank[sev] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if rank[out[i].Severity] != rank[out[j].Severity] {
			return rank[out[i].Severity] < rank[out[j].Severity]
		}
		if out[i].PackageName != out[j].PackageName {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// GET /api/cves?image=&artifact=&severity=&exclude=&id=&fixed=1&namespace=
// severity accepts a comma-separated include list; exclude accepts a
// comma-separated list of severities to drop (used by the SPA's severity
// chips, which start all "on" and turn individual severities off); fixed=1
// keeps only CVEs that have a fixed version available; namespace keeps only
// CVEs whose affected images run in that namespace. artifact is a
// case-insensitive substring match against the syft artifact (package) name.
func (s *Server) handleCVEs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	image := q.Get("image")
	namespace := q.Get("namespace")
	// multiple CVE IDs separated by spaces: a row matches when it contains
	// any of the tokens (the SPA expands named vulnerability groups into
	// these tokens client-side)
	idFilters := strings.Fields(strings.ToLower(q.Get("id")))
	artifactFilter := scanner.PackageNameFilter(q.Get("artifact"))
	fixedOnly := q.Get("fixed") == "1"

	severities := map[string]struct{}{}
	for _, sev := range strings.Split(q.Get("severity"), ",") {
		sev = strings.ToLower(strings.TrimSpace(sev))
		if sev != "" {
			severities[sev] = struct{}{}
		}
	}
	excluded := map[string]struct{}{}
	for _, sev := range strings.Split(q.Get("exclude"), ",") {
		sev = strings.ToLower(strings.TrimSpace(sev))
		if sev != "" {
			excluded[sev] = struct{}{}
		}
	}

	out := []cveOut{}
	for _, row := range s.cveRows() {
		if image != "" && row.Image != image {
			continue
		}
		if len(severities) > 0 {
			if _, ok := severities[row.Severity]; !ok {
				continue
			}
		}
		if _, skip := excluded[row.Severity]; skip {
			continue
		}
		if !artifactFilter(row.PackageName) {
			continue
		}
		if len(idFilters) > 0 && !matchesAnyID(row.ID, idFilters) {
			continue
		}
		if fixedOnly && len(row.FixedIn) == 0 {
			continue
		}
		if namespace != "" && !rowRunsInNamespace(row, namespace) {
			continue
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, out)
}

// matchesAnyID reports whether the CVE ID contains any of the given
// case-insensitive tokens.
func matchesAnyID(id string, tokens []string) bool {
	id = strings.ToLower(id)
	for _, token := range tokens {
		if strings.Contains(id, token) {
			return true
		}
	}
	return false
}

// rowRunsInNamespace reports whether the row's own image runs in the given
// namespace (a CVE row represents one package in one image).
func rowRunsInNamespace(row cveOut, namespace string) bool {
	for _, ref := range row.Images {
		if ref.Image == row.Image && ref.Namespace == namespace {
			return true
		}
	}
	return false
}

// namespaceNames returns the distinct namespaces of the workloads running
// scanned images, sorted.
func (s *Server) namespaceNames() []string {
	set := map[string]struct{}{}
	for _, res := range s.opts.Store.Snapshot("") {
		for _, inst := range res.Instances {
			if inst.Namespace != "" {
				set[inst.Namespace] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for ns := range set {
		out = append(out, ns)
	}
	sort.Strings(out)
	return out
}

// GET /api/named-vulns returns the named vulnerability groups (freshly
// fetched from GitHub at startup, or the embedded fallback copy).
func (s *Server) handleNamedVulns(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.namedVulnList())
}

// GET /api/namespaces returns the distinct namespaces of the workloads
// running scanned images (feeds the SPA's namespace selector).
func (s *Server) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.namespaceNames())
}

// artifactNames returns the distinct syft artifact (package) names of scanned
// images, optionally restricted to one image and filtered by substring q.
func (s *Server) artifactNames(image, q string) []string {
	filter := scanner.PackageNameFilter(q)
	names := map[string]struct{}{}
	for _, res := range s.opts.Store.Snapshot(image) {
		if res.Status != scanner.StatusScanned {
			continue
		}
		for _, a := range res.Artifacts {
			if filter(a.Name) {
				names[a.Name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// GET /api/artifacts?image=&q= returns the distinct syft artifact (package)
// names, used to feed the SPA's artifact-name filter suggestions.
func (s *Server) handleArtifacts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	writeJSON(w, http.StatusOK, s.artifactNames(q.Get("image"), q.Get("q")))
}

// exportSnapshot is the data embedded in an exported report.
type exportSnapshot struct {
	GeneratedAt      time.Time           `json:"generatedAt"`
	Status           map[string]any      `json:"status"`
	Images           []scanner.Summary   `json:"images"`
	Cves             []cveOut            `json:"cves"`
	Namespaces       []string            `json:"namespaces"`
	NamedVulns       []namedVuln         `json:"namedVulns"`
	Artifacts        []string            `json:"artifacts"`
	ArtifactsByImage map[string][]string `json:"artifactsByImage"`
}

// buildSnapshot collects the current results for embedding into an export.
func (s *Server) buildSnapshot() exportSnapshot {
	byImage := map[string][]string{}
	for _, res := range s.opts.Store.Snapshot("") {
		if res.Status != scanner.StatusScanned {
			continue
		}
		byImage[res.Image] = s.artifactNames(res.Image, "")
	}
	return exportSnapshot{
		GeneratedAt:      time.Now().UTC(),
		Status:           s.statusPayload(),
		Images:           s.opts.Store.Summaries(),
		Cves:             s.cveRows(),
		Namespaces:       s.namespaceNames(),
		NamedVulns:       s.namedVulnList(),
		Artifacts:        s.artifactNames("", ""),
		ArtifactsByImage: byImage,
	}
}

// ExportHTML renders the SPA as a single self-contained HTML file with the
// current results embedded as JSON, so it can be opened without the server
// (filters work offline against the frozen snapshot).
func (s *Server) ExportHTML() []byte {
	snap := s.buildSnapshot()
	data, err := json.Marshal(snap)
	if err != nil {
		data = []byte("{}")
	}
	// escape "</" so the JSON cannot break out of the <script> element
	data = bytes.ReplaceAll(data, []byte("</"), []byte(`<\/`))
	payload := append([]byte(`<script id="__artifactor_data" type="application/json">`), data...)
	payload = append(payload, []byte("</script>")...)
	return bytes.Replace(s.opts.SPA, []byte(exportMarker), payload, 1)
}

// GET /api/export downloads the self-contained report.
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="artifactor-report.html"`)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write(s.ExportHTML())
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if s.opts.Scanner == nil || s.opts.K8sErr != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "scanner not available: " + errString(s.opts.K8sErr)})
		return
	}
	if !s.opts.Store.TryStartScan() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "a scan is already running"})
		return
	}
	go func() {
		defer s.opts.Store.FinishScan()
		if err := s.opts.Scanner.RunOnce(context.Background()); err != nil && err != context.Canceled {
			s.opts.Store.SetDBError(err.Error())
		}
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "scan started"})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
