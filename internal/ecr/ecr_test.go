package ecr

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIsECRRegistry(t *testing.T) {
	cases := map[string]bool{
		"602401143452.dkr.ecr.sa-east-1.amazonaws.com": true,
		"123.dkr.ecr.us-east-1.amazonaws.com":          true,
		"123.dkr.ecr.cn-north-1.amazonaws.com.cn":      true,
		"ghcr.io":              false,
		"index.docker.io":      false,
		"registry.example.com": false,
		"602401143452.dkr.ecr.sa-east-1.amazonaws.com:443": false, // authorities carry no port for ECR
	}
	for registry, want := range cases {
		if got := IsECRRegistry(registry); got != want {
			t.Errorf("IsECRRegistry(%q) = %v, want %v", registry, got, want)
		}
	}
}

func TestRegionFromRegistry(t *testing.T) {
	cases := map[string]string{
		"602401143452.dkr.ecr.sa-east-1.amazonaws.com": "sa-east-1",
		"123.dkr.ecr.us-east-1.amazonaws.com":          "us-east-1",
		"123.dkr.ecr.cn-north-1.amazonaws.com.cn":      "cn-north-1",
		"ghcr.io": "",
	}
	for registry, want := range cases {
		if got := regionFromRegistry(registry); got != want {
			t.Errorf("regionFromRegistry(%q) = %q, want %q", registry, got, want)
		}
	}
}

func TestProviderCacheAndExpiry(t *testing.T) {
	now := time.Now()
	fetches := 0
	p := &Provider{
		cache: map[string]entry{},
		ttl:   time.Hour,
		now:   func() time.Time { return now },
		fetch: func(ctx context.Context, registry string) (string, string, error) {
			fetches++
			return "AWS", "token", nil
		},
	}

	for i := 0; i < 3; i++ {
		user, pass, err := p.Credentials(context.Background(), "123.dkr.ecr.us-east-1.amazonaws.com")
		if err != nil || user != "AWS" || pass != "token" {
			t.Fatalf("credentials = %q/%q, %v", user, pass, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("fetch calls = %d, want 1 (cached)", fetches)
	}

	// after the TTL the token is fetched again
	now = now.Add(2 * time.Hour)
	if _, _, err := p.Credentials(context.Background(), "123.dkr.ecr.us-east-1.amazonaws.com"); err != nil {
		t.Fatal(err)
	}
	if fetches != 2 {
		t.Fatalf("fetch calls = %d, want 2 (expired)", fetches)
	}
}

func TestProviderFetchError(t *testing.T) {
	p := &Provider{
		cache: map[string]entry{},
		ttl:   time.Hour,
		now:   time.Now,
		fetch: func(ctx context.Context, registry string) (string, string, error) {
			return "", "", errors.New("no creds")
		},
	}
	if _, _, err := p.Credentials(context.Background(), "123.dkr.ecr.us-east-1.amazonaws.com"); err == nil {
		t.Fatal("expected fetch error to propagate")
	}
}
