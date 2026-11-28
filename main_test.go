package main

import "testing"

func TestStartupScanDecision(t *testing.T) {
	tests := []struct {
		name        string
		hasScanner  bool
		hasProvider bool
		wantRun     bool
		wantWarning string
	}{
		{
			name:        "scanner and vulnerability database ready",
			hasScanner:  true,
			hasProvider: true,
			wantRun:     true,
		},
		{
			name:        "vulnerability database unavailable",
			hasScanner:  true,
			hasProvider: false,
			wantRun:     false,
			wantWarning: "startup scan skipped: vulnerability database unavailable",
		},
		{
			name:        "no scanner",
			hasScanner:  false,
			hasProvider: false,
			wantRun:     false,
			wantWarning: "startup scan skipped: no Kubernetes client available",
		},
		{
			name:        "no scanner even with a provider",
			hasScanner:  false,
			hasProvider: true,
			wantRun:     false,
			wantWarning: "startup scan skipped: no Kubernetes client available",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run, warning := startupScanDecision(tt.hasScanner, tt.hasProvider)
			if run != tt.wantRun {
				t.Errorf("run = %v, want %v", run, tt.wantRun)
			}
			if warning != tt.wantWarning {
				t.Errorf("warning = %q, want %q", warning, tt.wantWarning)
			}
			if run && warning != "" {
				t.Errorf("warning = %q on a runnable startup scan", warning)
			}
		})
	}
}
