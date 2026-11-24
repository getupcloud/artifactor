// Package scanner scans container images with syft (SBOM) and grype (CVE
// matching), both used as embedded Go libraries, and keeps the results in an
// in-memory store served by the API.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"

	"github.com/getupcloud/artifactor/internal/azure"
	"github.com/getupcloud/artifactor/internal/ecr"
	"github.com/getupcloud/artifactor/internal/gcp"
	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/logx"
	"github.com/getupcloud/artifactor/internal/registryauth"
)

// Scan status values.
const (
	StatusQueued   = "queued"
	StatusCanceled = "canceled"
	StatusScanning = "scanning"
	StatusScanned  = "scanned"
	StatusError    = "error"
)

// Severities ordered from most to least severe.
var SeverityOrder = []string{"critical", "high", "medium", "low", "negligible", "unknown"}

// Artifact is a package discovered by syft in an image.
type Artifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
	PURL    string `json:"purl,omitempty"`
}

// CVEArtifactLocation is one filesystem path of the artifact affected by
// a CVE, with the kind of path — package database entry ("package"), the
// artifact file itself ("filename"), a metadata file ("metadata") or any
// other path ("path") — used as the display label in the UI.
type CVEArtifactLocation struct {
	Path string `json:"path"`
	Kind string `json:"kind,omitempty"`
}

// CVE is a vulnerability found by grype on a package of an image.
type CVE struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	PackageName    string   `json:"package"`
	PackageVersion string   `json:"packageVersion"`
	PackageType    string   `json:"packageType"`
	FixedIn        []string `json:"fixedIn,omitempty"`
	Description    string   `json:"description,omitempty"`
	URLs           []string `json:"urls,omitempty"`
	DataSource     string   `json:"dataSource,omitempty"`
	Matcher        string   `json:"matcher,omitempty"`
	// PURL identifies the affected artifact (package) unambiguously;
	// Locations are the readable paths of the artifact in the image.
	PURL      string                `json:"purl,omitempty"`
	Locations []CVEArtifactLocation `json:"locations,omitempty"`
	// VexStatus/VexFile mark a CVE that a VEX document ignored
	// (not_affected or fixed): the status and the document that ignored it.
	VexStatus string `json:"vexStatus,omitempty"`
	VexFile   string `json:"vexFile,omitempty"`
}

// Result is the scan result for one image.
type Result struct {
	Image         string         `json:"image"`
	Status        string         `json:"status"`
	Error         string         `json:"error,omitempty"`
	StartedAt     *time.Time     `json:"startedAt,omitempty"`
	ScannedAt     *time.Time     `json:"scannedAt,omitempty"`
	Distro        string         `json:"distro,omitempty"`
	Instances     []k8s.Instance `json:"instances,omitempty"`
	Artifacts     []Artifact     `json:"-"`
	Cves          []CVE          `json:"-"`
	ArtifactCount int            `json:"artifactCount"`
	CVECount      int            `json:"cveCount"`
	Severities    map[string]int `json:"severities"`
	SBOM          []byte         `json:"-"` // syft JSON SBOM of the image (used by --export-sbom)
	Bytes         int64          `json:"-"` // bytes received for this image (compressed size pulled from the registry, or the SBOM file size)

	// raw grype matches and package context of the image (pre-VEX), kept so
	// the VEX documents can be re-applied without re-running the scan
	// (no image pull, no DB access, no SBOM regeneration). Read-only after
	// the result is stored; copies share the underlying matches.
	matches    *match.Matches
	pkgContext pkg.Context
}

// Summary is the API-facing projection of a Result.
type Summary struct {
	Image         string         `json:"image"`
	Status        string         `json:"status"`
	Error         string         `json:"error,omitempty"`
	ScannedAt     *time.Time     `json:"scannedAt,omitempty"`
	Distro        string         `json:"distro,omitempty"`
	ArtifactCount int            `json:"artifactCount"`
	CVECount      int            `json:"cveCount"`
	Severities    map[string]int `json:"severities"`
}

func (r *Result) summary() Summary {
	return Summary{
		Image:         r.Image,
		Status:        r.Status,
		Error:         r.Error,
		ScannedAt:     r.ScannedAt,
		Distro:        r.Distro,
		ArtifactCount: len(r.Artifacts),
		CVECount:      len(r.Cves),
		Severities:    r.Severities,
	}
}

// Store is a concurrency-safe in-memory collection of scan results.
type Store struct {
	mu           sync.RWMutex
	results      map[string]*Result
	images       []string
	scanning     bool
	discovering  bool               // true while a scan run is in its discovery phase
	cancelling   bool               // true from the cancel request until the run finishes
	scanCancel   context.CancelFunc // cancels the running scan (nil when idle)
	lastScanDone *time.Time
	dbError      string
	stats        ScanStats
}

func NewStore() *Store {
	return &Store{results: map[string]*Result{}}
}

// SetImages replaces the set of known images, keeping existing results.
func (s *Store) SetImages(images []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.images = append([]string(nil), images...)
	known := map[string]struct{}{}
	for _, img := range images {
		known[img] = struct{}{}
		if _, ok := s.results[img]; !ok {
			s.results[img] = &Result{Image: img, Status: StatusQueued, Severities: map[string]int{}}
		}
	}
	for img := range s.results {
		if _, ok := known[img]; !ok {
			delete(s.results, img)
		}
	}
}

func (s *Store) Images() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.images...)
}

func (s *Store) MarkScanning(img string, started time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.results[img]; ok {
		r.Status = StatusScanning
		r.Error = ""
		r.StartedAt = &started
	}
}

func (s *Store) Put(r Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Severities == nil {
		r.Severities = map[string]int{}
	}
	for _, c := range r.Cves {
		r.Severities[c.Severity]++
	}
	prev, ok := s.results[r.Image]
	if ok {
		r.StartedAt = prev.StartedAt
	}
	s.results[r.Image] = &r
}

// ReplaceCVEs replaces the CVEs of one image and recomputes the severity
// counts (used by the VEX reprocessing, which re-applies the documents to
// the stored matches without re-scanning).
func (s *Store) ReplaceCVEs(img string, cves []CVE) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.results[img]
	if !ok {
		return
	}
	r.Cves = append([]CVE(nil), cves...)
	r.Severities = map[string]int{}
	for _, c := range cves {
		r.Severities[c.Severity]++
	}
}

func (s *Store) Summaries() []Summary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Summary, 0, len(s.results))
	for _, img := range s.images {
		if r, ok := s.results[img]; ok {
			out = append(out, r.summary())
		}
	}
	return out
}

// Snapshot returns full copies of all results for the given image, or of all
// images when image is empty.
func (s *Store) Snapshot(image string) []Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Result{}
	for _, img := range s.images {
		if image != "" && img != image {
			continue
		}
		if r, ok := s.results[img]; ok {
			cp := *r
			cp.Artifacts = append([]Artifact(nil), r.Artifacts...)
			cp.Cves = append([]CVE(nil), r.Cves...)
			cp.Instances = append([]k8s.Instance(nil), r.Instances...)
			cp.SBOM = append([]byte(nil), r.SBOM...)
			out = append(out, cp)
		}
	}
	return out
}

// TryStartScan marks a scan run as started, atomically registering the cancel
// function that stops it; returns false if one is already running. Images
// canceled by a previous run go back to the queued state.
func (s *Store) TryStartScan(cancel context.CancelFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanning {
		return false
	}
	s.scanning = true
	s.scanCancel = cancel
	for _, r := range s.results {
		if r.Status == StatusCanceled {
			r.Status = StatusQueued
		}
	}
	return true
}

// CancelScan cancels the running scan, if any: the images that were being
// scanned or still waiting are marked canceled (their partial results are
// dropped by the workers once the context is canceled) and the store stays
// in the cancelling state until the run finishes. Returns false when no
// scan is running.
func (s *Store) CancelScan() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.scanning {
		return false
	}
	if s.scanCancel != nil {
		s.scanCancel()
	}
	for _, r := range s.results {
		if r.Status == StatusScanning || r.Status == StatusQueued {
			r.Status = StatusCanceled
			r.StartedAt = nil
		}
	}
	s.cancelling = true
	return true
}

func (s *Store) FinishScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanning = false
	s.cancelling = false
	s.scanCancel = nil
	now := time.Now().UTC()
	s.lastScanDone = &now
}

// IsCancelling reports whether a cancel was requested and the scan run has
// not finished yet.
func (s *Store) IsCancelling() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cancelling
}

func (s *Store) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanning
}

// SetDiscovering marks whether a scan run is in its discovery phase (the
// cluster API is being listed; no image is being scanned yet).
func (s *Store) SetDiscovering(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discovering = v
}

// IsDiscovering reports whether a scan run is in its discovery phase.
func (s *Store) IsDiscovering() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.discovering
}

func (s *Store) LastScanDone() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastScanDone == nil {
		return nil
	}
	t := *s.lastScanDone
	return &t
}

func (s *Store) SetDBError(err string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dbError = err
}

// SetStats records the metrics of the last completed scan run.
func (s *Store) SetStats(st ScanStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats = st
}

// Stats returns the metrics of the last completed scan run.
func (s *Store) Stats() ScanStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

func (s *Store) DBError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dbError
}

// Options configures a Scanner.
type Options struct {
	Namespaces    []string               // restrict scanning to these namespaces (empty = all)
	LabelSelector string                 // restrict discovery to pods matching this Kubernetes label selector (empty = all)
	FromSBOM      string                 // path to an SBOM file or directory of SBOM files (non-recursive): run grype only, skipping syft
	Provider      vulnerability.Provider // initial grype vulnerability DB provider (may be nil; set later via SetProvider)
	ECR           *ecr.Provider          // AWS ECR credential provider via the AWS chain/IRSA (nil disables)
	GCP           *gcp.Provider          // Google registry credential provider via GKE Workload Identity (nil disables)
	Azure         *azure.Provider        // ACR credential provider via Microsoft Entra Workload ID (nil disables)
	KeepSBOM      bool                   // retain the encoded syft SBOM per image in memory (needed by --export-sbom)
	Insecure      bool                   // skip TLS certificate verification when pulling images (self-signed registry certs)
	Platform      string
	Timeout       time.Duration
	Concurrency   int
	Store         *Store
	// VexDocs holds the resolved VEX documents (OpenVEX or CSAF, already
	// validated by ResolveVexFiles): the startup --vex files. The active
	// set can be replaced at runtime with SetVexDocs (uploads via the UI).
	VexDocs []VexDoc
}

// Scanner orchestrates discovery + syft/grype scanning of all cluster images.
type Scanner struct {
	opts     Options
	matchers []match.Matcher
	mu       sync.RWMutex
	provider vulnerability.Provider
	vexDocs  []VexDoc // active VEX documents (startup + UI uploads)
}

func New(opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 3
	}
	return &Scanner{
		opts:     opts,
		matchers: defaultMatchers(),
		provider: opts.Provider,
		vexDocs:  append([]VexDoc(nil), opts.VexDocs...),
	}
}

// SetVexDocs replaces the active VEX documents (the startup --vex files
// plus the documents uploaded via the UI). Images scanned afterwards use
// the new set; call ReprocessVex to re-apply it to the existing results.
func (s *Scanner) SetVexDocs(docs []VexDoc) {
	s.mu.Lock()
	s.vexDocs = append([]VexDoc(nil), docs...)
	s.mu.Unlock()
}

func (s *Scanner) currentVexDocs() []VexDoc {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]VexDoc(nil), s.vexDocs...)
}

// SetProvider replaces the grype vulnerability provider (e.g. once the DB
// finishes initializing in the background).
func (s *Scanner) SetProvider(p vulnerability.Provider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.provider = p
}

// Provider returns the current grype vulnerability provider (may be nil).
func (s *Scanner) Provider() vulnerability.Provider {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.provider
}

// defaultMatchers mirrors the matcher configuration grype's CLI uses by
// default.
func defaultMatchers() []match.Matcher {
	return matcher.NewDefaultMatchers(matcher.Config{
		Stock: stock.MatcherConfig{UseCPEs: true},
		Dpkg:  dpkg.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyZero},
		Rpm:   rpm.MatcherConfig{MissingEpochStrategy: version.MissingEpochStrategyAuto},
	})
}

// RunOnce discovers the current set of images of the given cluster and scans
// all of them. client is nil in --from-sbom mode (which does not use it).
func (s *Scanner) RunOnce(ctx context.Context, client *k8s.Client) error {
	// Return freed pages to the OS after the run: the Go runtime tends to
	// hold onto heap it no longer needs, which looks like a leak in RSS.
	defer debug.FreeOSMemory()

	if s.opts.FromSBOM != "" {
		return s.runFromSBOM(ctx)
	}
	if client == nil {
		return errors.New("no cluster selected")
	}

	start := time.Now()
	s.opts.Store.SetDiscovering(true)
	disc, err := client.Discover(ctx, s.opts.Namespaces, s.opts.LabelSelector)
	s.opts.Store.SetDiscovering(false)
	if err != nil {
		return fmt.Errorf("discover images: %w", err)
	}
	s.opts.Store.SetImages(disc.Images)
	logx.Infof("discovered %d unique image(s) in the cluster", len(disc.Images))

	jobs := make(chan string)
	var wg sync.WaitGroup
	var progress atomic.Int64
	var scanned atomic.Int64
	var totalBytes atomic.Int64
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for img := range jobs {
				if ctx.Err() != nil {
					continue // scan canceled: skip the remaining images
				}
				started := time.Now().UTC()
				n := progress.Add(1)
				s.opts.Store.MarkScanning(img, started)
				logx.Infof("scanning %s ... (%d/%d)", img, n, len(disc.Images))
				result := s.scanImage(ctx, img, disc.PullSecrets[img])
				if ctx.Err() != nil {
					continue // canceled: drop the partial result (CancelScan re-queued the image)
				}
				result.Instances = disc.Instances[img]
				s.opts.Store.Put(result)
				if result.Status == StatusScanned {
					scanned.Add(1)
				}
				totalBytes.Add(result.Bytes)
				switch result.Status {
				case StatusScanned:
					logx.Infof("scanned %s: %d artifacts, %d CVE(s) in %s (%d/%d)", img, len(result.Artifacts), len(result.Cves), time.Since(started).Round(time.Second), n, len(disc.Images))
				case StatusError:
					logx.Errorf("scan failed for %s: %s", img, result.Error)
				}
			}
		}()
	}
sendLoop:
	for _, img := range disc.Images {
		select {
		case jobs <- img:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	s.finishScanStats(start, scanned.Load(), totalBytes.Load())
	return ctx.Err()
}

// scanImage produces the SBOM for one image with syft and matches CVEs with
// grype. pullSecrets holds the raw docker config payloads that apply to the
// image; the first payload that carries an authority wins.
func (s *Scanner) scanImage(ctx context.Context, imageRef string, pullSecrets [][]byte) Result {
	result := Result{Image: imageRef, Status: StatusError, Severities: map[string]int{}}

	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()

	// Merge every applicable pull secret into one authority->credential map
	// (pod-level secrets come first and take precedence).
	merged := map[string]image.RegistryCredentials{}
	for _, payload := range pullSecrets {
		creds, err := registryauth.ParseDockerConfig(payload)
		if err != nil {
			logx.Warnf("ignoring unparseable pull secret for %s: %v", imageRef, err)
			continue
		}
		for authority, cred := range creds {
			if _, exists := merged[authority]; !exists {
				merged[authority] = cred
			}
		}
	}
	credentials := registryauth.CredentialsFor(merged, imageRef)

	// Cloud workload identities: images are usually pulled by the kubelet
	// with the pod/node identity (no pod imagePullSecret). When no
	// pull-secret credential matched, mint short-lived registry tokens from
	// the running identity — AWS ECR (chain/IRSA), Google registries (GKE
	// Workload Identity) and Azure ACR (Microsoft Entra Workload ID).
	if len(credentials) == 0 {
		authority := registryauth.AuthorityForImage(imageRef)
		switch {
		case s.opts.ECR != nil && ecr.IsECRRegistry(authority):
			username, password, err := s.opts.ECR.Credentials(ctx, authority)
			if err != nil {
				logx.Warnf("ecr credentials for %s: %v", authority, err)
			} else {
				credentials = append(credentials, image.RegistryCredentials{Authority: authority, Username: username, Password: password})
			}
		case s.opts.GCP != nil && gcp.IsGoogleRegistry(authority):
			username, password, err := s.opts.GCP.Credentials(ctx)
			if err != nil {
				logx.Warnf("gcp credentials for %s: %v", authority, err)
			} else {
				credentials = append(credentials, image.RegistryCredentials{Authority: authority, Username: username, Password: password})
			}
		case s.opts.Azure != nil && azure.IsACRRegistry(authority):
			username, password, err := s.opts.Azure.Credentials(ctx)
			if err != nil {
				logx.Warnf("azure credentials for %s: %v", authority, err)
			} else {
				credentials = append(credentials, image.RegistryCredentials{Authority: authority, Username: username, Password: password})
			}
		}
	}

	// 1. syft: generate the SBOM (pulls the image from its registry using
	//    the credentials above).
	sbomCfg := syft.DefaultCreateSBOMConfig()
	packages, pkgContext, sbo, err := pkg.Provide(imageRef, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			SBOMOptions: sbomCfg,
			RegistryOptions: &image.RegistryOptions{
				Credentials:           credentials,
				InsecureSkipTLSVerify: s.opts.Insecure,
			},
			Platform:               s.opts.Platform,
			DefaultImagePullSource: "registry",
		},
	})
	if err != nil {
		result.Error = fmt.Sprintf("syft: %v", err)
		return result
	}
	if pkgContext.Distro != nil {
		result.Distro = pkgContext.Distro.String()
	}
	// the compressed image size is what was pulled from the registry
	if md, ok := sbo.Source.Metadata.(source.ImageMetadata); ok {
		result.Bytes = md.Size
	}
	if s.opts.KeepSBOM {
		if encoded, err := encodeSyftJSON(*sbo); err == nil {
			result.SBOM = encoded
		} else {
			logx.Warnf("cannot encode syft SBOM for %s: %v", imageRef, err)
		}
	}

	result.Artifacts = packageArtifacts(*sbo)

	// 2. grype: match CVEs against the SBOM packages. The raw matches are
	//    kept for later VEX reprocessing (no rescan needed).
	var matches *match.Matches
	result.Cves, matches, err = s.matchCVEs(ctx, packages, pkgContext)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.matches = matches
	result.pkgContext = pkgContext

	result.Status = StatusScanned
	now := time.Now().UTC()
	result.ScannedAt = &now
	return result
}

// packageArtifacts flattens the packages of an SBOM into the artifact list
// shown in the UI.
func packageArtifacts(s sbom.SBOM) []Artifact {
	artifacts := make([]Artifact, 0, s.Artifacts.Packages.PackageCount())
	for _, p := range s.Artifacts.Packages.Sorted() {
		artifacts = append(artifacts, Artifact{
			Name:    p.Name,
			Version: p.Version,
			Type:    string(p.Type),
			PURL:    p.PURL,
		})
	}
	sort.Slice(artifacts, func(i, j int) bool {
		return artifacts[i].Name < artifacts[j].Name
	})
	return artifacts
}

// matchCVEs runs grype's vulnerability matcher over the given packages,
// then applies the active VEX documents. The raw (pre-VEX) matches are
// returned so the caller can store them for later VEX reprocessing.
func (s *Scanner) matchCVEs(ctx context.Context, packages []pkg.Package, pkgContext pkg.Context) ([]CVE, *match.Matches, error) {
	provider := s.Provider()
	if provider == nil {
		return nil, nil, errors.New("vulnerability database unavailable (see /api/status)")
	}
	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              s.matchers,
		NormalizeByCVE:        true,
	}
	matches, _, err := vm.FindMatchesContext(ctx, packages, pkgContext)
	if err != nil {
		return nil, nil, fmt.Errorf("grype: %w", err)
	}
	cves, err := applyVex(matches, pkgContext, s.currentVexDocs())
	if err != nil {
		return nil, nil, err
	}
	return cves, matches, nil
}

// ReprocessVex re-applies the active VEX documents to the stored matches
// of every scanned image, without re-running the scan: no image pull, no
// vulnerability DB access and no SBOM regeneration. Called after the VEX
// set changes (files uploaded or removed via the UI).
func (s *Scanner) ReprocessVex() error {
	docs := s.currentVexDocs()
	for _, res := range s.opts.Store.Snapshot("") {
		if res.matches == nil {
			continue
		}
		cves, err := applyVex(res.matches, res.pkgContext, docs)
		if err != nil {
			return err
		}
		s.opts.Store.ReplaceCVEs(res.Image, cves)
	}
	return nil
}

// applyVex applies the VEX documents to the matches: matches ignored by a
// document (not_affected/fixed) are kept in the CVE list, marked with
// their VEX status and the name of the document that ignored them (one
// processor per document, applied in a chain — the grype library does not
// expose the per-document origin when all documents are processed
// together).
func applyVex(matches *match.Matches, pkgContext pkg.Context, docs []VexDoc) ([]CVE, error) {
	cves := []CVE{}
	for _, m := range matches.Sorted() {
		cves = append(cves, cveFromMatch(m))
	}
	remaining := matches
	for _, doc := range docs {
		p, err := vex.NewProcessor(vex.ProcessorOptions{Documents: []string{doc.Path}})
		if err != nil {
			return nil, fmt.Errorf("vex document %q: %w", doc.Path, err)
		}
		var ignored []match.IgnoredMatch
		remaining, ignored, err = p.ApplyVEX(&pkgContext, remaining, nil)
		if err != nil {
			return nil, fmt.Errorf("vex: %w", err)
		}
		for _, im := range ignored {
			c := cveFromMatch(im.Match)
			if len(im.AppliedIgnoreRules) > 0 {
				c.VexStatus = im.AppliedIgnoreRules[0].VexStatus
			}
			c.VexFile = doc.Name
			cves = append(cves, c)
		}
	}
	return cves, nil
}

// cveFromMatch projects one grype match into the API-facing CVE struct.
func cveFromMatch(m match.Match) CVE {
	c := CVE{
		ID:             m.Vulnerability.ID,
		PackageName:    m.Package.Name,
		PackageVersion: m.Package.Version,
		PackageType:    string(m.Package.Type),
		FixedIn:        m.Vulnerability.Fix.Versions,
		Matcher:        matcherTypes(m.Details.Matchers()),
		PURL:           m.Package.PURL,
		Locations:      packageLocations(m.Package),
	}
	if md := m.Vulnerability.Metadata; md != nil {
		c.Severity = normalizeSeverity(md.Severity)
		c.Description = md.Description
		c.URLs = md.URLs
		c.DataSource = md.DataSource
	} else {
		c.Severity = "unknown"
	}
	return c
}

// packageLocations returns the readable paths of a package in the image
// (access path when present, real path otherwise), each with its display
// kind, in stable order and without empty paths or duplicates.
func packageLocations(p pkg.Package) []CVEArtifactLocation {
	locations := []CVEArtifactLocation{}
	seen := map[string]struct{}{}
	for _, loc := range p.Locations.ToSlice() {
		path := loc.Path()
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		locations = append(locations, CVEArtifactLocation{Path: path, Kind: locationKind(p.Type)})
	}
	return locations
}

// locationKind classifies the location of a package of the given type:
// package database entries, the artifact file itself, metadata files or
// any other path (see CVEArtifactLocation).
func locationKind(t syftPkg.Type) string {
	switch t {
	case syftPkg.AlpmPkg, syftPkg.ApkPkg, syftPkg.DebPkg, syftPkg.RpmPkg, syftPkg.PortagePkg:
		return "package"
	case syftPkg.BinaryPkg, syftPkg.JavaPkg, syftPkg.JenkinsPluginPkg, syftPkg.LinuxKernelPkg,
		syftPkg.LinuxKernelModulePkg, syftPkg.GraalVMNativeImagePkg, syftPkg.AppleAppBundlePkg, syftPkg.ModelPkg:
		return "filename"
	case syftPkg.PythonPkg, syftPkg.CondaPkg, syftPkg.Rpkg:
		return "metadata"
	default:
		return "path"
	}
}

// runFromSBOM scans the SBOM file(s) configured via Options.FromSBOM with
// grype only: syft is never executed and no image is downloaded.
func (s *Scanner) runFromSBOM(ctx context.Context) error {
	paths, err := sbomInputPaths(s.opts.FromSBOM)
	if err != nil {
		return fmt.Errorf("read sbom input: %w", err)
	}
	if len(paths) == 0 {
		return fmt.Errorf("no SBOM files in %s", s.opts.FromSBOM)
	}

	start := time.Now()

	// The store needs the complete image list up front (queued entries in a
	// stable order), so do a light pass to resolve each file's image name
	// before scanning. Files are decoded again during the scan; decoding a
	// local SBOM is cheap compared to the grype matching that follows.
	names := make([]string, 0, len(paths))
	seen := map[string]int{}
	for _, p := range paths {
		name := sbomNameFromPath(p)
		if sbo, err := decodeSBOMFile(p); err == nil {
			if n := sbomImageName(*sbo); n != "" {
				name = n
			}
		} else {
			logx.Warnf("%v (recording it as failed)", err)
		}
		seen[name]++
		if n := seen[name]; n > 1 {
			name = fmt.Sprintf("%s (%d)", name, n)
		}
		names = append(names, name)
	}
	s.opts.Store.SetImages(names)
	logx.Infof("scanning %d SBOM file(s) with grype (syft skipped)", len(paths))

	jobs := make(chan int)
	var wg sync.WaitGroup
	var progress atomic.Int64
	var scanned atomic.Int64
	var totalBytes atomic.Int64
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					continue // scan canceled: skip the remaining files
				}
				started := time.Now().UTC()
				n := progress.Add(1)
				s.opts.Store.MarkScanning(names[j], started)
				logx.Infof("scanning %s ... (%d/%d)", paths[j], n, len(paths))
				result := s.scanSBOMFile(ctx, paths[j])
				if ctx.Err() != nil {
					continue // canceled: drop the partial result (CancelScan re-queued the image)
				}
				result.Image = names[j]
				s.opts.Store.Put(result)
				if result.Status == StatusScanned {
					scanned.Add(1)
				}
				totalBytes.Add(result.Bytes)
				switch result.Status {
				case StatusScanned:
					logx.Infof("scanned %s: %d artifacts, %d CVE(s) in %s (%d/%d)", names[j], len(result.Artifacts), len(result.Cves), time.Since(started).Round(time.Second), n, len(paths))
				case StatusError:
					logx.Errorf("scan failed for %s: %s", names[j], result.Error)
				}
			}
		}()
	}
sendLoop:
	for j := range paths {
		select {
		case jobs <- j:
		case <-ctx.Done():
			break sendLoop
		}
	}
	close(jobs)
	wg.Wait()
	s.finishScanStats(start, scanned.Load(), totalBytes.Load())
	return ctx.Err()
}

// scanSBOMFile matches CVEs for one SBOM file with grype. The image name is
// taken from the SBOM source metadata when available (otherwise from the
// file name).
func (s *Scanner) scanSBOMFile(ctx context.Context, path string) Result {
	result := Result{Image: sbomNameFromPath(path), Status: StatusError, Severities: map[string]int{}}

	ctx, cancel := context.WithTimeout(ctx, s.opts.Timeout)
	defer cancel()

	f, err := os.Open(path)
	if err != nil {
		result.Error = fmt.Sprintf("open: %v", err)
		return result
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil {
		result.Bytes = fi.Size()
	}

	// grype decodes the SBOM (any syft-supported format) and returns the
	// packages + distro context needed for matching; syft is never executed.
	packages, pkgContext, sbo, err := pkg.ProvideFromReader(f, pkg.ProviderConfig{})
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if name := sbomImageName(*sbo); name != "" {
		result.Image = name
	}
	if pkgContext.Distro != nil {
		result.Distro = pkgContext.Distro.String()
	}
	if s.opts.KeepSBOM {
		if encoded, err := encodeSyftJSON(*sbo); err == nil {
			result.SBOM = encoded
		} else {
			logx.Warnf("cannot encode syft SBOM for %s: %v", path, err)
		}
	}
	result.Artifacts = packageArtifacts(*sbo)

	var matches *match.Matches
	result.Cves, matches, err = s.matchCVEs(ctx, packages, pkgContext)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.matches = matches
	result.pkgContext = pkgContext

	result.Status = StatusScanned
	now := time.Now().UTC()
	result.ScannedAt = &now
	return result
}

// decodeSBOMFile decodes one SBOM file, auto-detecting its format.
func decodeSBOMFile(path string) (*sbom.SBOM, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	sbo, _, _, err := format.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("decode SBOM %s: %w", path, err)
	}
	return sbo, nil
}

// sbomInputPaths returns the SBOM file paths for input: the single file, or
// every regular file directly inside a directory (non-recursive).
func sbomInputPaths(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{input}, nil
	}
	entries, err := os.ReadDir(input)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		paths = append(paths, filepath.Join(input, e.Name()))
	}
	sort.Strings(paths)
	return paths, nil
}

// sbomNameFromPath is the fallback image name for an SBOM file: the file
// base name without extension.
func sbomNameFromPath(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

// sbomImageName returns the original image reference recorded in the SBOM
// source metadata when the SBOM was generated from a container image.
func sbomImageName(s sbom.SBOM) string {
	if md, ok := s.Source.Metadata.(source.ImageMetadata); ok && md.UserInput != "" {
		return md.UserInput
	}
	return ""
}

func matcherTypes(types []match.MatcherType) string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, string(t))
	}
	return strings.Join(names, ",")
}

// encodeSyftJSON encodes an SBOM in syft's own JSON format (the same output
// `syft <image> -o syft-json` produces).
func encodeSyftJSON(s sbom.SBOM) ([]byte, error) {
	for _, enc := range format.Encoders() {
		if enc.ID() == "syft-json" {
			return format.Encode(s, enc)
		}
	}
	return nil, errors.New("syft-json format encoder not found")
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown"
	}
}

// PackageNameFilter returns true when the given syft artifact name matches q
// (case-insensitive substring).
func PackageNameFilter(q string) func(string) bool {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return func(string) bool { return true }
	}
	return func(name string) bool {
		return strings.Contains(strings.ToLower(name), q)
	}
}
