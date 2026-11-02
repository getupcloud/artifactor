// Package ecr authenticates to AWS Elastic Container Registry using the
// standard AWS credential chain (env, shared config, and — inside EKS —
// IRSA / pod identity via web identity token files). ECR credentials are
// short-lived, so tokens are fetched lazily and cached for a short TTL.
package ecr

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
)

// ecrRegistryPattern matches ECR registries:
// <account>.dkr.ecr.<region>.amazonaws.com (also .com.cn).
var ecrRegistryPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`)

// IsECRRegistry reports whether the given registry authority is an AWS ECR
// registry.
func IsECRRegistry(registry string) bool {
	return ecrRegistryPattern.MatchString(registry)
}

// regionFromRegistry extracts the AWS region from an ECR registry host, e.g.
// "123456789012.dkr.ecr.sa-east-1.amazonaws.com" -> "sa-east-1".
func regionFromRegistry(registry string) string {
	parts := strings.Split(registry, ".")
	if len(parts) >= 4 {
		return parts[3]
	}
	return ""
}

type entry struct {
	username string
	password string
	expires  time.Time
}

// Provider returns (cached) ECR registry credentials.
type Provider struct {
	mu    sync.Mutex
	cache map[string]entry
	ttl   time.Duration
	now   func() time.Time
	fetch func(ctx context.Context, registry string) (string, string, error)
}

// NewProvider returns a Provider backed by the AWS credential chain.
func NewProvider() *Provider {
	return &Provider{
		cache: map[string]entry{},
		ttl:   time.Hour,
		now:   time.Now,
		fetch: awsFetchToken,
	}
}

// Credentials returns username/password for the given ECR registry, fetching
// (and caching) a fresh authorization token when needed.
func (p *Provider) Credentials(ctx context.Context, registry string) (string, string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.cache[registry]; ok && p.now().Before(e.expires) {
		return e.username, e.password, nil
	}
	username, password, err := p.fetch(ctx, registry)
	if err != nil {
		return "", "", err
	}
	p.cache[registry] = entry{username: username, password: password, expires: p.now().Add(p.ttl)}
	return username, password, nil
}

// awsFetchToken calls ecr:GetAuthorizationToken and decodes the base64
// "user:pass" payload. The token works for pulls in the registry's region.
func awsFetchToken(ctx context.Context, registry string) (string, string, error) {
	region := regionFromRegistry(registry)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return "", "", fmt.Errorf("load aws config: %w", err)
	}
	client := awsecr.NewFromConfig(cfg)
	out, err := client.GetAuthorizationToken(ctx, &awsecr.GetAuthorizationTokenInput{})
	if err != nil {
		return "", "", fmt.Errorf("ecr GetAuthorizationToken: %w", err)
	}
	for _, ad := range out.AuthorizationData {
		if ad.AuthorizationToken == nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(*ad.AuthorizationToken)
		if err != nil {
			continue
		}
		username, password, ok := strings.Cut(string(decoded), ":")
		if !ok {
			continue
		}
		return username, password, nil
	}
	return "", "", fmt.Errorf("ecr GetAuthorizationToken returned no authorization data")
}
