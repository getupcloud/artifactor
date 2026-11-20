// Package gcp authenticates to Google container registries (gcr.io and
// Artifact Registry *.pkg.dev) using the GKE Workload Identity metadata
// server: the pod's bound GCP service account is exchanged for a short-lived
// OAuth2 access token, used as the registry password (username
// "oauth2accesstoken"). Tokens are fetched lazily and cached by their
// expires_in lifetime.
package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sync"
	"time"
)

// googleRegistryPattern matches Google container registries:
// gcr.io, *.gcr.io (us.gcr.io, marketplace.gcr.io, …) and Artifact
// Registry *.pkg.dev (us-docker.pkg.dev, europe-docker.pkg.dev, …).
// registry.k8s.io/k8s.gcr.io are public and intentionally left out.
var (
	gcrPattern = regexp.MustCompile(`^([a-z0-9-]+\.)*gcr\.io$`)
	garPattern = regexp.MustCompile(`^[a-z0-9-]+\.pkg\.dev$`)
)

// IsGoogleRegistry reports whether the given registry authority is a Google
// container registry.
func IsGoogleRegistry(registry string) bool {
	// k8s.gcr.io is Google-hosted but public (no auth needed).
	if registry == "k8s.gcr.io" {
		return false
	}
	return gcrPattern.MatchString(registry) || garPattern.MatchString(registry)
}

// metadataTokenURL is the Workload Identity metadata server token endpoint
// (the cloud-platform scope covers Artifact Registry reads).
var metadataTokenURL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https://www.googleapis.com/auth/cloud-platform"

type entry struct {
	token   string
	expires time.Time
}

// Provider returns (cached) Google registry credentials minted from the GKE
// metadata server.
type Provider struct {
	mu    sync.Mutex
	cache entry
	ttl   time.Duration
	now   func() time.Time
	fetch func(ctx context.Context) (string, time.Duration, error)
}

// NewProvider returns a Provider backed by the GKE metadata server.
func NewProvider() *Provider {
	return &Provider{
		ttl:   time.Hour,
		now:   time.Now,
		fetch: metadataFetchToken,
	}
}

// Credentials returns username/password for a Google registry, fetching (and
// caching) a fresh metadata server token when needed.
func (p *Provider) Credentials(ctx context.Context) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.now().Before(p.cache.expires) {
		return "oauth2accesstoken", p.cache.token, nil
	}
	token, ttl, err := p.fetch(ctx)
	if err != nil {
		return "", "", err
	}
	p.cache = entry{token: token, expires: p.now().Add(ttl)}
	return "oauth2accesstoken", token, nil
}

// metadataFetchToken calls the metadata server and returns the access token
// plus its lifetime (expires_in minus a safety margin).
func metadataFetchToken(ctx context.Context) (string, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataTokenURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("metadata server: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("metadata server: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("metadata server: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("metadata server: parse token: %w", err)
	}
	if out.AccessToken == "" || out.ExpiresIn <= 0 {
		return "", 0, errors.New("metadata server: token response missing access_token/expires_in")
	}
	ttl := time.Duration(out.ExpiresIn)*time.Second - 5*time.Minute
	if ttl < time.Minute {
		ttl = time.Minute
	}
	return out.AccessToken, ttl, nil
}
