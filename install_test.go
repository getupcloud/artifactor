package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestRenderManifests(t *testing.T) {
	data, err := renderManifests("", "")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"kind: Namespace",
		"kind: ServiceAccount",
		"kind: ClusterRole",
		"kind: ClusterRoleBinding",
		"kind: Deployment",
		"kind: Service",
		"name: artifactor",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("manifests missing %q", want)
		}
	}
	if strings.Contains(text, "kind: Secret") {
		t.Error("imagePullSecret included without --image-token-env")
	}
	if got := strings.Count(text, "\n---\n"); got != 6 {
		t.Errorf("separator count = %d, want 6", got)
	}
}

func TestRenderManifestsImageOverride(t *testing.T) {
	data, err := renderManifests("registry.example.com/team/artifactor:v9", "")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "image: registry.example.com/team/artifactor:v9") {
		t.Error("image override not applied")
	}
	if strings.Contains(text, "ghcr.io/getupcloud/artifactor:0.0.1") {
		t.Error("original image still present after override")
	}
}

func TestDockerConfigSecretData(t *testing.T) {
	secret, err := dockerConfigSecretData("tok123")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("secret data is not base64: %v", err)
	}
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("secret data is not JSON: %v", err)
	}
	entry, ok := cfg.Auths["ghcr.io"]
	if !ok {
		t.Fatalf("auths = %v, want ghcr.io entry", cfg.Auths)
	}
	decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "gh:tok123" {
		t.Errorf("auth = %q, want gh:tok123", decoded)
	}

	// "user:token" form keeps the user part
	secret, _ = dockerConfigSecretData("myuser:mytok")
	raw, _ = base64.StdEncoding.DecodeString(secret)
	_ = json.Unmarshal(raw, &cfg)
	decoded, _ = base64.StdEncoding.DecodeString(cfg.Auths["ghcr.io"].Auth)
	if string(decoded) != "myuser:mytok" {
		t.Errorf("auth = %q, want myuser:mytok", decoded)
	}
}

func TestRenderManifestsWithSecret(t *testing.T) {
	secretData, err := dockerConfigSecretData("tok123")
	if err != nil {
		t.Fatal(err)
	}
	data, err := renderManifests("", secretData)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"kind: Secret",
		"name: docker-ghcr",
		"type: kubernetes.io/dockerconfigjson",
		".dockerconfigjson: " + secretData,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("secret manifest missing %q", want)
		}
	}
	// the secret must come before the deployment that references it
	if strings.Index(text, "kind: Secret") > strings.Index(text, "kind: Deployment") {
		t.Error("secret manifest must be rendered before the deployment")
	}
	if got := strings.Count(text, "\n---\n"); got != 7 {
		t.Errorf("separator count = %d, want 7 (with secret)", got)
	}
}

func TestInstallDump(t *testing.T) {
	out := captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump"})
	})
	if !strings.Contains(out, "kind: Namespace") || !strings.Contains(out, "kind: Deployment") {
		t.Errorf("install --dump output missing manifests: %q", out[:min(len(out), 120)])
	}
	if strings.Contains(out, "kind: Secret") {
		t.Error("install --dump included the secret without --image-token-env")
	}

	out = captureStdout(t, func() {
		runInstallCmd("uninstall", []string{"--dump", "--image", "img:v1"})
	})
	if !strings.Contains(out, "image: img:v1") {
		t.Error("uninstall --dump --image did not apply the override")
	}

	t.Setenv("REGISTRY_TOKEN", "tok123")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env"})
	})
	if !strings.Contains(out, "kind: Secret") {
		t.Error("install --dump --image-token-env did not include the secret")
	}
	if !strings.Contains(out, "name: docker-ghcr") {
		t.Error("install --dump --image-token-env missing docker-ghcr secret")
	}

	t.Setenv("MY_TOKEN", "tok456")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env=MY_TOKEN"})
	})
	secretData, _ := dockerConfigSecretData("tok456")
	if !strings.Contains(out, ".dockerconfigjson: "+secretData) {
		t.Error("install --dump --image-token-env=MY_TOKEN did not use MY_TOKEN")
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out)
}
