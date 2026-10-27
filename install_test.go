package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestRenderManifests(t *testing.T) {
	data, err := renderManifests("")
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
	if got := strings.Count(text, "\n---\n"); got != 6 {
		t.Errorf("separator count = %d, want 6", got)
	}
}

func TestRenderManifestsImageOverride(t *testing.T) {
	data, err := renderManifests("registry.example.com/team/artifactor:v9")
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

func TestInstallDump(t *testing.T) {
	out := captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump"})
	})
	if !strings.Contains(out, "kind: Namespace") || !strings.Contains(out, "kind: Deployment") {
		t.Errorf("install --dump output missing manifests: %q", out[:min(len(out), 120)])
	}

	out = captureStdout(t, func() {
		runInstallCmd("uninstall", []string{"--dump", "--image", "img:v1"})
	})
	if !strings.Contains(out, "image: img:v1") {
		t.Error("uninstall --dump --image did not apply the override")
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
