// Package clusters keeps a small in-memory registry of the Kubernetes
// clusters the web UI can scan: the cluster discovered at startup plus
// clusters added from the SPA by pasting a kubeconfig. Kubeconfig contents
// never leave the process (only names, modes, contexts and errors are
// exposed).
package clusters

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/getupcloud/artifactor/internal/k8s"
)

// ErrDuplicate is returned by Add when the cluster name already exists.
var ErrDuplicate = errors.New("a cluster with this name already exists")

// ErrLastCluster is returned by Remove when the cluster is the only one left.
var ErrLastCluster = errors.New("cannot remove the last cluster")

// Info is the API-facing projection of an entry. It deliberately excludes
// the kubeconfig contents (credentials).
type Info struct {
	Name           string   `json:"name"`
	Mode           string   `json:"mode"`
	Contexts       []string `json:"contexts,omitempty"`
	CurrentContext string   `json:"currentContext,omitempty"`
	Error          string   `json:"error,omitempty"`
}

// Entry is one registered cluster.
type Entry struct {
	name           string
	mode           string
	client         *k8s.Client
	kubeconfig     []byte // raw contents; never exposed
	contexts       []string
	currentContext string
	err            error
}

// Manager registers the clusters available to the scanner.
type Manager struct {
	mu       sync.RWMutex
	entries  map[string]*Entry
	order    []string
	selected string
}

// New returns an empty Manager.
func New() *Manager {
	return &Manager{entries: map[string]*Entry{}}
}

// AddStartup registers the cluster the process started with (in-cluster or
// the local kubeconfig). err carries the client construction failure, if
// any; such an entry is listed with its error and cannot be scanned.
func (m *Manager) AddStartup(name, mode string, client *k8s.Client, kubeconfig []byte, err error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[name]; exists {
		return fmt.Errorf("cluster %q already exists", name)
	}
	e := &Entry{name: name, mode: mode, client: client, kubeconfig: kubeconfig, err: err}
	if mode == "kubeconfig" && err == nil {
		e.contexts, e.currentContext, _ = k8s.KubeconfigContexts(kubeconfig)
	}
	return m.addLocked(e)
}

// Add registers a cluster from raw kubeconfig contents. The name must be
// non-empty and unique. The kubeconfig must parse and build a client with
// its current-context (or the first context when none is set).
func (m *Manager) Add(name, kubeconfig string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("cluster name is required")
	}
	contexts, current, err := k8s.KubeconfigContexts([]byte(kubeconfig))
	if err != nil {
		return err
	}
	if len(contexts) == 0 {
		return errors.New("kubeconfig has no contexts")
	}
	client, err := k8s.NewFromKubeconfig([]byte(kubeconfig), current)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.entries[name]; exists {
		return ErrDuplicate
	}
	return m.addLocked(&Entry{
		name:           name,
		mode:           "kubeconfig",
		client:         client,
		kubeconfig:     []byte(kubeconfig),
		contexts:       contexts,
		currentContext: current,
	})
}

// addLocked appends an entry and selects the first one. The caller holds the
// lock.
func (m *Manager) addLocked(e *Entry) error {
	m.entries[e.name] = e
	m.order = append(m.order, e.name)
	if m.selected == "" {
		m.selected = e.name
	}
	return nil
}

// Remove deletes a cluster. The last remaining cluster cannot be removed;
// removing the selected cluster selects the first remaining one.
func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[name]; !ok {
		return fmt.Errorf("cluster %q not found", name)
	}
	if len(m.order) == 1 {
		return ErrLastCluster
	}
	delete(m.entries, name)
	for i, n := range m.order {
		if n == name {
			m.order = append(m.order[:i], m.order[i+1:]...)
			break
		}
	}
	if m.selected == name {
		m.selected = m.order[0]
	}
	return nil
}

// Select makes name the active cluster for scans.
func (m *Manager) Select(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[name]; !ok {
		return fmt.Errorf("cluster %q not found", name)
	}
	m.selected = name
	return nil
}

// SetContext switches the context used for a cluster, rebuilding its client
// with the new context. On failure the previous client is kept.
func (m *Manager) SetContext(name, context string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[name]
	if !ok {
		return fmt.Errorf("cluster %q not found", name)
	}
	if !contains(e.contexts, context) {
		return fmt.Errorf("context %q not found in cluster %q", context, name)
	}
	client, err := k8s.NewFromKubeconfig(e.kubeconfig, context)
	if err != nil {
		return err
	}
	e.client = client
	e.currentContext = context
	return nil
}

// Client returns the client of a cluster.
func (m *Manager) Client(name string) (*k8s.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.clientLocked(name)
}

func (m *Manager) clientLocked(name string) (*k8s.Client, error) {
	e, ok := m.entries[name]
	if !ok {
		return nil, fmt.Errorf("cluster %q not found", name)
	}
	if e.client == nil {
		return nil, fmt.Errorf("cluster %q is not available: %v", name, e.err)
	}
	return e.client, nil
}

// SelectedClient returns the client of the selected cluster.
func (m *Manager) SelectedClient() (*k8s.Client, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.selected == "" {
		return nil, errors.New("no cluster selected")
	}
	return m.clientLocked(m.selected)
}

// SelectedName returns the name of the selected cluster ("" when empty).
func (m *Manager) SelectedName() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.selected
}

// Selected returns the Info of the selected cluster, or nil when the manager
// is empty.
func (m *Manager) Selected() *Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.infoLocked(m.selected)
}

// List returns the Info of every cluster in insertion order.
func (m *Manager) List() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Info, 0, len(m.order))
	for _, name := range m.order {
		if info := m.infoLocked(name); info != nil {
			out = append(out, *info)
		}
	}
	return out
}

// infoLocked projects an entry (nil for unknown names). The caller holds the
// lock.
func (m *Manager) infoLocked(name string) *Info {
	if name == "" {
		return nil
	}
	e, ok := m.entries[name]
	if !ok {
		return nil
	}
	info := &Info{
		Name:           e.name,
		Mode:           e.mode,
		Contexts:       append([]string(nil), e.contexts...),
		CurrentContext: e.currentContext,
	}
	if e.err != nil {
		info.Error = e.err.Error()
	}
	return info
}

// contains reports whether list contains v.
func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}
