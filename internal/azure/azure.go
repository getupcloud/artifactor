// Package azure authenticates to Azure Container Registry using the
// Microsoft Entra Workload ID of AKS: the projected Kubernetes service
// account token (AZURE_FEDERATED_TOKEN_FILE) is exchanged — client
// assertion flow — for a short-lived Entra ID access token scoped to
// containerregistry.azure.net, used as the registry password. Tokens are
// fetched lazily and cached by their expires_in lifetime.
package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// acrRegistryPattern matches Azure Container Registry registries:
// *.azurecr.io and the sovereign clouds *.azurecr.us/.cn/.de.
var acrRegistryPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*\.azurecr\.(io|us|cn|de)$`)

// IsACRRegistry reports whether the given registry authority is an Azure
// Container Registry.
func IsACRRegistry(registry string) bool {
	return acrRegistryPattern.MatchString(registry)
}

// acrUsername is the conventional username for ACR pulls authenticated with
// an Entra ID access token (the identity is carried by the token itself).
const acrUsername = "00000000-0000-0000-0000-000000000000"

// defaultAuthorityHost is the Entra ID (Azure AD) token endpoint host; the
// AZURE_AUTHORITY_HOST env overrides it (sovereign clouds).
var defaultAuthorityHost = "https://login.microsoftonline.com"

// tokenScope is the ACR access scope.
const tokenScope = "https://containerregistry.azure.net/.default"

type entry struct {
	token   string
	expires time.Time
}

// Provider returns (cached) ACR credentials minted from the AKS workload
// identity (Entra ID federated credential exchange).
type Provider struct {
	mu       sync.Mutex
	cache    entry
	ttl      time.Duration
	now      func() time.Time
	exchange func(ctx context.Context) (string, time.Duration, error)
}

// NewProvider returns a Provider backed by the AKS workload identity envs.
func NewProvider() *Provider {
	return &Provider{
		ttl:      time.Hour,
		now:      time.Now,
		exchange: exchangeToken,
	}
}

// Credentials returns username/password for an ACR registry, fetching (and
// caching) a fresh Entra ID access token when needed.
func (p *Provider) Credentials(ctx context.Context) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.now().Before(p.cache.expires) {
		return acrUsername, p.cache.token, nil
	}
	token, ttl, err := p.exchange(ctx)
	if err != nil {
		return "", "", err
	}
	p.cache = entry{token: token, expires: p.now().Add(ttl)}
	return acrUsername, token, nil
}

// exchangeToken runs the client assertion flow against the Entra ID token
// endpoint using the AKS workload identity environment (the federated token
// file is re-read on every exchange — the kubelet rotates it).
func exchangeToken(ctx context.Context) (string, time.Duration, error) {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	switch {
	case tenantID == "":
		return "", 0, errors.New("AZURE_TENANT_ID is not set (not running with AKS workload identity)")
	case clientID == "":
		return "", 0, errors.New("AZURE_CLIENT_ID is not set (not running with AKS workload identity)")
	case tokenFile == "":
		return "", 0, errors.New("AZURE_FEDERATED_TOKEN_FILE is not set (not running with AKS workload identity)")
	}
	assertion, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", 0, fmt.Errorf("read federated token file: %w", err)
	}
	authority := os.Getenv("AZURE_AUTHORITY_HOST")
	if authority == "" {
		authority = defaultAuthorityHost
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", clientID)
	form.Set("scope", tokenScope)
	form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	form.Set("client_assertion", string(assertion))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(authority, "/")+"/"+url.PathEscape(tenantID)+"/oauth2/v2.0/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("entra token endpoint: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", 0, fmt.Errorf("entra token endpoint: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("entra token endpoint: HTTP %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("entra token endpoint: parse token: %w", err)
	}
	if out.AccessToken == "" || out.ExpiresIn <= 0 {
		return "", 0, errors.New("entra token endpoint: response missing access_token/expires_in")
	}
	ttl := time.Duration(out.ExpiresIn)*time.Second - 5*time.Minute
	if ttl < time.Minute {
		ttl = time.Minute
	}
	return out.AccessToken, ttl, nil
}
