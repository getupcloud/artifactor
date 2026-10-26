package registryauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func dockerConfigJSON(t *testing.T, auths map[string]map[string]string) []byte {
	t.Helper()
	payload := map[string]any{"auths": auths}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseDockerConfig(t *testing.T) {
	data := dockerConfigJSON(t, map[string]map[string]string{
		"https://index.docker.io/v1/": {"auth": base64.StdEncoding.EncodeToString([]byte("user:pass"))},
		"ghcr.io":                     {"username": "u2", "password": "p2"},
	})
	creds, err := ParseDockerConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := creds["index.docker.io"]; got.Username != "user" || got.Password != "pass" {
		t.Errorf("docker hub cred = %+v, want user/pass", got)
	}
	if _, ok := creds["docker.io"]; !ok {
		t.Error("expected docker.io alias entry")
	}
	if got := creds["ghcr.io"]; got.Username != "u2" || got.Password != "p2" {
		t.Errorf("ghcr cred = %+v, want u2/p2", got)
	}
}

func TestParseLegacyDockercfg(t *testing.T) {
	legacy := map[string]map[string]string{
		"registry.example.com": {"auth": base64.StdEncoding.EncodeToString([]byte("a:b"))},
	}
	data, _ := json.Marshal(legacy)
	creds, err := ParseDockerConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := creds["registry.example.com"]; got.Username != "a" || got.Password != "b" {
		t.Errorf("legacy cred = %+v, want a/b", got)
	}
}

func TestAuthorityForImage(t *testing.T) {
	cases := map[string]string{
		"nginx":                            "index.docker.io",
		"nginx:1.25":                       "index.docker.io",
		"library/nginx":                    "index.docker.io",
		"ghcr.io/org/app:v1":               "ghcr.io",
		"registry.example.com:5000/team/a": "registry.example.com:5000",
		"localhost:5000/app":               "localhost:5000",
		"registry.example.com/team/app@sha256:abc": "registry.example.com",
		"myregistry:5000/app":                      "myregistry:5000",
	}
	for ref, want := range cases {
		if got := AuthorityForImage(ref); got != want {
			t.Errorf("AuthorityForImage(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestCredentialsFor(t *testing.T) {
	data := dockerConfigJSON(t, map[string]map[string]string{
		"https://index.docker.io/v1/": {"auth": base64.StdEncoding.EncodeToString([]byte("u:p"))},
		"quay.io":                     {"auth": base64.StdEncoding.EncodeToString([]byte("q:q"))},
	})
	byAuthority, err := ParseDockerConfig(data)
	if err != nil {
		t.Fatal(err)
	}

	if got := CredentialsFor(byAuthority, "nginx"); len(got) != 1 || got[0].Username != "u" {
		t.Errorf("nginx creds = %+v, want docker hub u/p", got)
	}
	if got := CredentialsFor(byAuthority, "quay.io/org/img"); len(got) != 1 || got[0].Username != "q" {
		t.Errorf("quay creds = %+v, want q/q", got)
	}
	if got := CredentialsFor(byAuthority, "gcr.io/other/img"); len(got) != 0 {
		t.Errorf("gcr.io creds = %+v, want none", got)
	}
}
