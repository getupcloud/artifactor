package gcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIsGoogleRegistry(t *testing.T) {
	cases := map[string]bool{
		"gcr.io":                      true,
		"us.gcr.io":                   true,
		"eu.gcr.io":                   true,
		"marketplace.gcr.io":          true,
		"us-docker.pkg.dev":           true,
		"europe-west1-docker.pkg.dev": true,
		"ghcr.io":                     false,
		"index.docker.io":             false,
		"quay.io":                     false,
		"registry.example.com":        false,
		"registry.k8s.io":             false,
		"k8s.gcr.io":                  false,
		"fakegcr.io":                  false,
	}
	for registry, want := range cases {
		if got := IsGoogleRegistry(registry); got != want {
			t.Errorf("IsGoogleRegistry(%q) = %v, want %v", registry, got, want)
		}
	}
}

func TestProviderCacheAndExpiry(t *testing.T) {
	now := time.Now()
	fetches := 0
	p := &Provider{
		ttl: time.Hour,
		now: func() time.Time { return now },
		fetch: func(ctx context.Context) (string, time.Duration, error) {
			fetches++
			return "token", time.Hour, nil
		},
	}

	for i := 0; i < 3; i++ {
		user, pass, err := p.Credentials(context.Background())
		if err != nil || user != "oauth2accesstoken" || pass != "token" {
			t.Fatalf("credentials = %q/%q, %v", user, pass, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("fetch calls = %d, want 1 (cached)", fetches)
	}

	// after the TTL the token is fetched again
	now = now.Add(2 * time.Hour)
	if _, _, err := p.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetches != 2 {
		t.Fatalf("fetch calls = %d, want 2 (expired)", fetches)
	}
}

func TestProviderFetchError(t *testing.T) {
	p := &Provider{
		ttl: time.Hour,
		now: time.Now,
		fetch: func(ctx context.Context) (string, time.Duration, error) {
			return "", 0, errors.New("no metadata server")
		},
	}
	if _, _, err := p.Credentials(context.Background()); err == nil {
		t.Fatal("expected fetch error to propagate")
	}
}

func TestMetadataFetchToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			t.Errorf("missing Metadata-Flavor header")
		}
		if r.URL.Query().Get("scopes") != "https://www.googleapis.com/auth/cloud-platform" {
			t.Errorf("scopes = %q", r.URL.Query().Get("scopes"))
		}
		w.Write([]byte(`{"access_token":"tok123","expires_in":3600}`))
	}))
	defer srv.Close()

	old := metadataTokenURL
	metadataTokenURL = srv.URL + "?scopes=https://www.googleapis.com/auth/cloud-platform"
	defer func() { metadataTokenURL = old }()

	token, ttl, err := metadataFetchToken(context.Background())
	if err != nil || token != "tok123" {
		t.Fatalf("token = %q, %v", token, err)
	}
	if ttl != 3600*time.Second-5*time.Minute {
		t.Fatalf("ttl = %v, want 3600s minus 5m margin", ttl)
	}
}

func TestMetadataFetchTokenError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not here"))
	}))
	defer srv.Close()

	old := metadataTokenURL
	metadataTokenURL = srv.URL + "?scopes=https://www.googleapis.com/auth/cloud-platform"
	defer func() { metadataTokenURL = old }()

	if _, _, err := metadataFetchToken(context.Background()); err == nil {
		t.Fatal("expected error for non-200 metadata response")
	}
}
