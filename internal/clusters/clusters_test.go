package clusters

import (
	"errors"
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

func TestAddListSelectRemove(t *testing.T) {
	m := New()
	if err := m.Add("prod", testKubeconfig); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("staging", testKubeconfig); err != nil {
		t.Fatal(err)
	}

	if got := m.SelectedName(); got != "prod" { // first added is selected
		t.Errorf("selected = %q, want prod", got)
	}
	list := m.List()
	if len(list) != 2 || list[0].Name != "prod" || list[1].Name != "staging" {
		t.Fatalf("list = %+v", list)
	}
	if len(list[0].Contexts) != 2 || list[0].CurrentContext != "ctx-beta" {
		t.Errorf("prod info = %+v", list[0])
	}
	if list[0].Error != "" {
		t.Errorf("prod error = %q, want empty", list[0].Error)
	}

	client, err := m.SelectedClient()
	if err != nil || client == nil {
		t.Fatalf("SelectedClient = %v, %v", client, err)
	}

	// select the other cluster
	if err := m.Select("staging"); err != nil {
		t.Fatal(err)
	}
	if got := m.SelectedName(); got != "staging" {
		t.Errorf("selected = %q, want staging", got)
	}
	sel := m.Selected()
	if sel == nil || sel.Name != "staging" {
		t.Fatalf("Selected = %+v", sel)
	}

	// removing the selected cluster reselects the first remaining one
	if err := m.Remove("staging"); err != nil {
		t.Fatal(err)
	}
	if got := m.SelectedName(); got != "prod" {
		t.Errorf("selected after remove = %q, want prod", got)
	}
	if _, err := m.Client("staging"); err == nil {
		t.Error("removed cluster still resolvable")
	}

	// the last cluster cannot be removed
	if err := m.Remove("prod"); !errors.Is(err, ErrLastCluster) {
		t.Errorf("remove last cluster err = %v, want ErrLastCluster", err)
	}

	// unknown names
	if err := m.Select("nope"); err == nil {
		t.Error("Select(unknown) succeeded")
	}
	if err := m.Remove("nope"); err == nil {
		t.Error("Remove(unknown) succeeded")
	}
}

func TestAddErrors(t *testing.T) {
	m := New()
	if err := m.Add("", testKubeconfig); err == nil {
		t.Error("empty name accepted")
	}
	if err := m.Add("prod", "garbage"); err == nil {
		t.Error("invalid kubeconfig accepted")
	}
	if err := m.Add("prod", testKubeconfig); err != nil {
		t.Fatal(err)
	}
	if err := m.Add("prod", testKubeconfig); !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate add err = %v, want ErrDuplicate", err)
	}
}

func TestSetContext(t *testing.T) {
	m := New()
	if err := m.Add("prod", testKubeconfig); err != nil {
		t.Fatal(err)
	}
	if err := m.SetContext("prod", "ctx-alpha"); err != nil {
		t.Fatal(err)
	}
	list := m.List()
	if list[0].CurrentContext != "ctx-alpha" {
		t.Errorf("current context = %q, want ctx-alpha", list[0].CurrentContext)
	}
	if _, err := m.SelectedClient(); err != nil {
		t.Errorf("client after context switch: %v", err)
	}

	// invalid context: error, previous context kept
	if err := m.SetContext("prod", "ctx-nope"); err == nil {
		t.Error("unknown context accepted")
	}
	if list := m.List(); list[0].CurrentContext != "ctx-alpha" {
		t.Errorf("current context after failed switch = %q, want ctx-alpha", list[0].CurrentContext)
	}
	if err := m.SetContext("nope", "ctx-alpha"); err == nil {
		t.Error("SetContext on unknown cluster succeeded")
	}
}

func TestAddStartup(t *testing.T) {
	m := New()
	// in-cluster startup: no contexts, selected automatically
	if err := m.AddStartup("in-cluster", "in-cluster", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := m.SelectedName(); got != "in-cluster" {
		t.Errorf("selected = %q, want in-cluster", got)
	}
	if _, err := m.SelectedClient(); err == nil {
		t.Error("client without client did not error")
	}

	// startup with a client error: listed with the error, no client
	m2 := New()
	if err := m2.AddStartup("default", "kubeconfig", nil, []byte(testKubeconfig), errors.New("boom")); err != nil {
		t.Fatal(err)
	}
	list := m2.List()
	if len(list) != 1 || list[0].Error != "boom" || len(list[0].Contexts) != 0 {
		t.Errorf("startup with error = %+v", list)
	}

	// kubeconfig startup derives contexts from the file
	m3 := New()
	if err := m3.AddStartup("default", "kubeconfig", nil, []byte(testKubeconfig), nil); err != nil {
		t.Fatal(err)
	}
	list = m3.List()
	if len(list[0].Contexts) != 2 || list[0].CurrentContext != "ctx-beta" {
		t.Errorf("kubeconfig startup info = %+v", list[0])
	}

	// duplicate startup name
	if err := m.AddStartup("in-cluster", "in-cluster", nil, nil, nil); err == nil {
		t.Error("duplicate startup name accepted")
	}
}
