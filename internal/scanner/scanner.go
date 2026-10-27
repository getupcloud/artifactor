// Package scanner scans container images with syft (SBOM) and grype (CVE
// matching), both used as embedded Go libraries, and keeps the results in an
// in-memory store served by the API.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/matcher"
	"github.com/anchore/grype/grype/matcher/dpkg"
	"github.com/anchore/grype/grype/matcher/rpm"
	"github.com/anchore/grype/grype/matcher/stock"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"

	"github.com/getupcloud/artifactor/internal/ecr"
	"github.com/getupcloud/artifactor/internal/k8s"
	"github.com/getupcloud/artifactor/internal/registryauth"
)

// Scan status values.
const (
	StatusQueued   = "queued"
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
	lastScanDone *time.Time
	dbError      string
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

// TryStartScan marks a scan run as started; returns false if one is already
// running.
func (s *Store) TryStartScan() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.scanning {
		return false
	}
	s.scanning = true
	return true
}

func (s *Store) FinishScan() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanning = false
	now := time.Now().UTC()
	s.lastScanDone = &now
}

func (s *Store) IsScanning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanning
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

func (s *Store) DBError() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dbError
}

// Options configures a Scanner.
type Options struct {
	Client      *k8s.Client
	Namespaces  []string               // restrict scanning to these namespaces (empty = all)
	Provider    vulnerability.Provider // initial grype vulnerability DB provider (may be nil; set later via SetProvider)
	ECR         *ecr.Provider          // AWS ECR credential provider via the AWS chain/IRSA (nil disables)
	KeepSBOM    bool                   // retain the encoded syft SBOM per image in memory (needed by --export-sbom)
	Platform    string
	Timeout     time.Duration
	Concurrency int
	Store       *Store
	Logger      *log.Logger
}

// Scanner orchestrates discovery + syft/grype scanning of all cluster images.
type Scanner struct {
	opts     Options
	matchers []match.Matcher
	logger   *log.Logger
	mu       sync.RWMutex
	provider vulnerability.Provider
}

func New(opts Options) *Scanner {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 3
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	return &Scanner{
		opts:     opts,
		matchers: defaultMatchers(),
		logger:   opts.Logger,
		provider: opts.Provider,
	}
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

// RunOnce discovers the current set of images and scans all of them.
func (s *Scanner) RunOnce(ctx context.Context) error {
	// Return freed pages to the OS after the run: the Go runtime tends to
	// hold onto heap it no longer needs, which looks like a leak in RSS.
	defer debug.FreeOSMemory()

	disc, err := s.opts.Client.Discover(ctx, s.opts.Namespaces)
	if err != nil {
		return fmt.Errorf("discover images: %w", err)
	}
	s.opts.Store.SetImages(disc.Images)
	s.logger.Printf("discovered %d unique image(s) in the cluster", len(disc.Images))

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < s.opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for img := range jobs {
				started := time.Now().UTC()
				s.opts.Store.MarkScanning(img, started)
				s.logger.Printf("scanning %s ...", img)
				result := s.scanImage(ctx, img, disc.PullSecrets[img])
				result.Instances = disc.Instances[img]
				s.opts.Store.Put(result)
				switch result.Status {
				case StatusScanned:
					s.logger.Printf("scanned %s: %d artifacts, %d CVE(s) in %s", img, len(result.Artifacts), len(result.Cves), time.Since(started).Round(time.Second))
				case StatusError:
					s.logger.Printf("scan failed for %s: %s", img, result.Error)
				}
			}
		}()
	}
	for _, img := range disc.Images {
		select {
		case jobs <- img:
		case <-ctx.Done():
			break
		}
	}
	close(jobs)
	wg.Wait()
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
			s.logger.Printf("ignoring unparseable pull secret for %s: %v", imageRef, err)
			continue
		}
		for authority, cred := range creds {
			if _, exists := merged[authority]; !exists {
				merged[authority] = cred
			}
		}
	}
	credentials := registryauth.CredentialsFor(merged, imageRef)

	// AWS ECR images are usually pulled by the kubelet with node IAM roles
	// (no pod imagePullSecret). When no pull-secret credential matched, fall
	// back to the AWS credential chain (IRSA/pod identity) to mint a fresh
	// registry token.
	if len(credentials) == 0 && s.opts.ECR != nil {
		if authority := registryauth.AuthorityForImage(imageRef); ecr.IsECRRegistry(authority) {
			if username, password, err := s.opts.ECR.Credentials(ctx, authority); err != nil {
				s.logger.Printf("ecr credentials for %s: %v", authority, err)
			} else {
				credentials = append(credentials, image.RegistryCredentials{
					Authority: authority,
					Username:  username,
					Password:  password,
				})
			}
		}
	}

	// 1. syft: generate the SBOM (pulls the image from its registry using
	//    the credentials above).
	sbomCfg := syft.DefaultCreateSBOMConfig()
	packages, pkgContext, sbo, err := pkg.Provide(imageRef, pkg.ProviderConfig{
		SyftProviderConfig: pkg.SyftProviderConfig{
			SBOMOptions:            sbomCfg,
			RegistryOptions:        &image.RegistryOptions{Credentials: credentials},
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
	if s.opts.KeepSBOM {
		if encoded, err := encodeSyftJSON(*sbo); err == nil {
			result.SBOM = encoded
		} else {
			s.logger.Printf("warning: cannot encode syft SBOM for %s: %v", imageRef, err)
		}
	}

	for _, p := range sbo.Artifacts.Packages.Sorted() {
		result.Artifacts = append(result.Artifacts, Artifact{
			Name:    p.Name,
			Version: p.Version,
			Type:    string(p.Type),
			PURL:    p.PURL,
		})
	}
	sort.Slice(result.Artifacts, func(i, j int) bool {
		return result.Artifacts[i].Name < result.Artifacts[j].Name
	})

	// 2. grype: match CVEs against the SBOM packages.
	provider := s.Provider()
	if provider == nil {
		result.Error = "vulnerability database unavailable (see /api/status)"
		return result
	}
	vm := grype.VulnerabilityMatcher{
		VulnerabilityProvider: provider,
		Matchers:              s.matchers,
		NormalizeByCVE:        true,
	}
	matches, _, err := vm.FindMatchesContext(ctx, packages, pkgContext)
	if err != nil {
		result.Error = fmt.Sprintf("grype: %v", err)
		return result
	}

	for _, m := range matches.Sorted() {
		c := CVE{
			ID:             m.Vulnerability.ID,
			PackageName:    m.Package.Name,
			PackageVersion: m.Package.Version,
			PackageType:    string(m.Package.Type),
			FixedIn:        m.Vulnerability.Fix.Versions,
			Matcher:        matcherTypes(m.Details.Matchers()),
		}
		if md := m.Vulnerability.Metadata; md != nil {
			c.Severity = normalizeSeverity(md.Severity)
			c.Description = md.Description
			c.URLs = md.URLs
			c.DataSource = md.DataSource
		} else {
			c.Severity = "unknown"
		}
		result.Cves = append(result.Cves, c)
	}

	result.Status = StatusScanned
	now := time.Now().UTC()
	result.ScannedAt = &now
	return result
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
