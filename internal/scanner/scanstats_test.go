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
