package k8s

import (
	"strings"
	"testing"
)

// testKubeconfig is a minimal valid kubeconfig with two contexts.
const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: cluster-one
  cluster:
    server: https://127.0.0.1:6443
contexts:
- name: ctx-beta
  context:
    cluster: cluster-one
    user: user-one
- name: ctx-alpha
  context:
    cluster: cluster-one
    user: user-one
current-context: ctx-beta
users:
- name: user-one
  user:
    token: abc123
`

func TestKubeconfigContexts(t *testing.T) {
	names, current, err := KubeconfigContexts([]byte(testKubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "ctx-alpha" || names[1] != "ctx-beta" { // sorted
		t.Fatalf("contexts = %v, want [ctx-alpha ctx-beta]", names)
	}
	if current != "ctx-beta" {
		t.Errorf("current = %q, want ctx-beta", current)
	}

	// no current-context: the first (sorted) context wins
	noCurrent := strings.Replace(testKubeconfig, "current-context: ctx-beta", "", 1)
	names, current, err = KubeconfigContexts([]byte(noCurrent))
	if err != nil {
		t.Fatal(err)
	}
	if current != "ctx-alpha" {
		t.Errorf("current without current-context = %q, want ctx-alpha", current)
	}

	// invalid YAML
	if _, _, err := KubeconfigContexts([]byte("not: [valid")); err == nil {
		t.Error("expected parse error for invalid kubeconfig")
	}
}

func TestNewFromKubeconfig(t *testing.T) {
	client, err := NewFromKubeconfig([]byte(testKubeconfig), "ctx-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if client.cs == nil || client.dyn == nil {
		t.Fatal("client interfaces not built")
	}

	// unknown context: clientcmd validation rejects it
	if _, err := NewFromKubeconfig([]byte(testKubeconfig), "ctx-nope"); err == nil {
		t.Error("expected error for unknown context")
	}

	// invalid YAML
	if _, err := NewFromKubeconfig([]byte("garbage"), "ctx-alpha"); err == nil {
		t.Error("expected parse error for invalid kubeconfig")
	}
}
