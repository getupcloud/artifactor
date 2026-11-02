package scanner

import "testing"

func TestFormatBytes(t *testing.T) {
	cases := map[int64]string{
		0:                  "0 B",
		512:                "512 B",
		1024:               "1.0 KiB",
		1536:               "1.5 KiB",
		1024 * 1024:        "1.0 MiB",
		1536 * 1024:        "1.5 MiB",
		1024 * 1024 * 1024: "1.0 GiB",
		1234567890:         "1.1 GiB",
	}
	for in, want := range cases {
		if got := formatBytes(in); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestStoreScanStats(t *testing.T) {
	st := NewStore()
	if st.Stats().Images != 0 || st.Stats().Bytes != 0 {
		t.Errorf("fresh store stats = %+v, want zero", st.Stats())
	}
	st.SetStats(ScanStats{Images: 3, DurationSec: 60, AvgSecPerImg: 20, Bytes: 1500, BytesPerSec: 25})
	got := st.Stats()
	if got.Images != 3 || got.DurationSec != 60 || got.AvgSecPerImg != 20 || got.Bytes != 1500 || got.BytesPerSec != 25 {
		t.Errorf("stats = %+v", got)
	}
}

func TestRegistryStats(t *testing.T) {
	st := NewStore()
	st.SetImages([]string{
		"ghcr.io/acme/app:1",
		"ghcr.io/acme/db:2",
		"docker.io/library/alpine:3.20",
		"quay.io/x/y:1",
		"gcr.io/x/y:1", // never attempted: stays queued
		"ghcr.io/acme/tool:3",
	})
	st.Put(Result{Image: "ghcr.io/acme/app:1", Status: StatusScanned})
	st.Put(Result{Image: "ghcr.io/acme/db:2", Status: StatusError, Error: "syft: unauthorized"})
	st.Put(Result{Image: "docker.io/library/alpine:3.20", Status: StatusScanned})
	st.Put(Result{Image: "quay.io/x/y:1", Status: StatusError, Error: "vulnerability database unavailable (see /api/status)"})
	st.Put(Result{Image: "ghcr.io/acme/tool:3", Status: StatusError, Error: "syft: timeout"})

	got := New(Options{Store: st}).registryStats()
	if len(got) != 3 {
		t.Fatalf("registryStats = %+v, want 3 registries", got)
	}
	want := []RegistryStats{
		{Registry: "ghcr.io", Total: 3, Errors: 2},
		{Registry: "docker.io", Total: 1, Errors: 0},
		{Registry: "quay.io", Total: 1, Errors: 0},
	}
	for i, w := range want {
		if got[i].Registry != w.Registry || got[i].Total != w.Total || got[i].Errors != w.Errors {
			t.Fatalf("registryStats[%d] = %+v, want %+v", i, got[i], w)
		}
	}
	if want, have := 2.0/3.0, got[0].ErrorRate; have != want {
		t.Fatalf("ghcr.io errorRate = %v, want %v", have, want)
	}
	if got[2].ErrorRate != 0 {
		t.Fatalf("quay.io errorRate = %v, want 0 (DB error is not an access error)", got[2].ErrorRate)
	}

	// --from-sbom runs never touch a registry
	if regs := New(Options{Store: st, FromSBOM: "/tmp/x"}).registryStats(); regs != nil {
		t.Fatalf("registryStats for from-sbom = %+v, want nil", regs)
	}
}
