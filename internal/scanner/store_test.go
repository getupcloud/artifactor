package scanner

import (
	"testing"
	"time"
)

func TestStoreDiscovering(t *testing.T) {
	s := NewStore()
	if s.IsDiscovering() {
		t.Fatal("new store reports discovering")
	}
	s.SetDiscovering(true)
	if !s.IsDiscovering() {
		t.Fatal("SetDiscovering(true) not visible")
	}
	s.SetDiscovering(false)
	if s.IsDiscovering() {
		t.Fatal("SetDiscovering(false) not visible")
	}
}

func TestStoreTryStartScan(t *testing.T) {
	s := NewStore()
	canceled := false
	if !s.TryStartScan(func() { canceled = true }) {
		t.Fatal("first TryStartScan rejected")
	}
	if s.TryStartScan(func() { t.Error("second cancel must not be registered") }) {
		t.Fatal("second TryStartScan accepted while scanning")
	}
	s.FinishScan()
	if !s.TryStartScan(func() { canceled = true }) {
		t.Fatal("TryStartScan rejected after FinishScan")
	}
	s.FinishScan()
	if canceled {
		t.Error("cancel called without CancelScan")
	}
}

func TestStoreCancelScan(t *testing.T) {
	s := NewStore()
	if s.CancelScan() {
		t.Fatal("CancelScan returned true while idle")
	}
	s.SetImages([]string{"done:1", "running:1", "waiting:1"})
	now := time.Now().UTC()
	s.MarkScanning("running:1", now)
	s.Put(Result{Image: "done:1", Status: StatusScanned, Severities: map[string]int{}})

	canceled := false
	if !s.TryStartScan(func() { canceled = true }) {
		t.Fatal("TryStartScan rejected")
	}
	if !s.CancelScan() {
		t.Fatal("CancelScan returned false while scanning")
	}
	if !canceled {
		t.Error("cancel function not invoked")
	}

	for _, res := range s.Snapshot("") {
		switch res.Image {
		case "done:1":
			if res.Status != StatusScanned {
				t.Errorf("done:1 status = %s, want scanned", res.Status)
			}
		case "running:1":
			if res.Status != StatusQueued {
				t.Errorf("running:1 status = %s, want queued", res.Status)
			}
			if res.StartedAt != nil {
				t.Errorf("running:1 StartedAt = %v, want nil", res.StartedAt)
			}
		case "waiting:1":
			if res.Status != StatusQueued {
				t.Errorf("waiting:1 status = %s, want queued", res.Status)
			}
		}
	}
}

func TestStoreFinishScanClearsCancel(t *testing.T) {
	s := NewStore()
	canceled := false
	if !s.TryStartScan(func() { canceled = true }) {
		t.Fatal("TryStartScan rejected")
	}
	s.FinishScan()
	if s.CancelScan() {
		t.Fatal("CancelScan returned true after FinishScan")
	}
	if canceled {
		t.Error("cancel function invoked after FinishScan")
	}
}
