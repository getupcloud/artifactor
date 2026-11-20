package azure

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIsACRRegistry(t *testing.T) {
	cases := map[string]bool{
		"myregistry.azurecr.io":  true,
		"myregistry.azurecr.us":  true,
		"myregistry.azurecr.cn":  true,
		"myregistry.azurecr.de":  true,
		"ghcr.io":                false,
		"index.docker.io":        false,
		"quay.io":                false,
		"us-docker.pkg.dev":      false,
		"fakeazurecr.io":         false,
		"myregistry.azurecr.com": false,
	}
	for registry, want := range cases {
		if got := IsACRRegistry(registry); got != want {
			t.Errorf("IsACRRegistry(%q) = %v, want %v", registry, got, want)
		}
	}
}

func TestProviderCacheAndExpiry(t *testing.T) {
	now := time.Now()
	fetches := 0
	p := &Provider{
		ttl: time.Hour,
		now: func() time.Time { return now },
		exchange: func(ctx context.Context) (string, time.Duration, error) {
			fetches++
			return "token", time.Hour, nil
		},
	}

	for i := 0; i < 3; i++ {
		user, pass, err := p.Credentials(context.Background())
		if err != nil || user != acrUsername || pass != "token" {
			t.Fatalf("credentials = %q/%q, %v", user, pass, err)
		}
	}
	if fetches != 1 {
		t.Fatalf("exchange calls = %d, want 1 (cached)", fetches)
	}

	now = now.Add(2 * time.Hour)
	if _, _, err := p.Credentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fetches != 2 {
		t.Fatalf("exchange calls = %d, want 2 (expired)", fetches)
	}
}

func TestProviderExchangeError(t *testing.T) {
	p := &Provider{
		ttl: time.Hour,
		now: time.Now,
		exchange: func(ctx context.Context) (string, time.Duration, error) {
			return "", 0, errors.New("exchange failed")
		},
	}
	if _, _, err := p.Credentials(context.Background()); err == nil {
		t.Fatal("expected exchange error to propagate")
	}
}

func TestExchangeToken(t *testing.T) {
	var gotForm url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/my-tenant/oauth2/v2.0/token") {
			t.Errorf("path = %q", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		gotForm = r.PostForm
		if gotForm.Get("grant_type") != "client_credentials" ||
			gotForm.Get("client_id") != "client-1" ||
			gotForm.Get("scope") != tokenScope ||
			gotForm.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" ||
			gotForm.Get("client_assertion") != "sa-token" {
			t.Errorf("form = %v", gotForm)
		}
		w.Write([]byte(`{"access_token":"aad-token","expires_in":3600}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("sa-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AZURE_TENANT_ID", "my-tenant")
	t.Setenv("AZURE_CLIENT_ID", "client-1")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	t.Setenv("AZURE_AUTHORITY_HOST", srv.URL)

	token, ttl, err := exchangeToken(context.Background())
	if err != nil || token != "aad-token" {
		t.Fatalf("token = %q, %v", token, err)
	}
	if ttl != 3600*time.Second-5*time.Minute {
		t.Fatalf("ttl = %v, want 3600s minus 5m margin", ttl)
	}
}

func TestExchangeTokenMissingEnv(t *testing.T) {
	t.Setenv("AZURE_TENANT_ID", "")
	t.Setenv("AZURE_CLIENT_ID", "")
	t.Setenv("AZURE_FEDERATED_TOKEN_FILE", "")
	if _, _, err := exchangeToken(context.Background()); err == nil {
		t.Fatal("expected error without workload identity envs")
	}
}
