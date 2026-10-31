package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestDecodeOpenshiftManifests(t *testing.T) {
	objs, err := decodeOpenshiftManifests()
	if err != nil {
		t.Fatal(err)
	}
	if len(objs) != 3 {
		t.Fatalf("decoded %d objects, want 3", len(objs))
	}
	kinds := map[string]bool{}
	names := map[string]bool{}
	for _, obj := range objs {
		kinds[obj.GetObjectKind().GroupVersionKind().Kind] = true
		if meta, ok := obj.(metav1.Object); ok {
			names[meta.GetName()] = true
		}
	}
	for _, want := range []string{"SecurityContextConstraints", "ClusterRole", "ClusterRoleBinding"} {
		if !kinds[want] {
			t.Errorf("missing kind %s", want)
		}
	}
	for _, want := range []string{"artifactor", "artifactor-scc"} {
		if !names[want] {
			t.Errorf("missing name %s", want)
		}
	}
	// the SCC is not in the client-go scheme: it must decode as unstructured
	for _, obj := range objs {
		if obj.GetObjectKind().GroupVersionKind().Kind == "SecurityContextConstraints" {
			if _, ok := obj.(*unstructured.Unstructured); !ok {
				t.Errorf("SCC decoded as %T, want *unstructured.Unstructured", obj)
			}
		}
	}
}

func TestScanPodArgs(t *testing.T) {
	args := scanPodArgs(inClusterOpts{
		Namespaces:   []string{"a", "b"},
		Concurrency:  5,
		DBAutoUpdate: false,
		DBCACert:     "/local/ca.pem",
		DBDirect:     true,
		Platform:     "linux/amd64",
		ScanTimeout:  20 * time.Minute,
		ECRAuth:      false,
		KeepSBOM:     false,
		Insecure:     true,
		IgnoreDB:     true,
		CustomerName: "acme",
		ClusterName:  "prod",
		LogLevel:     "debug",
	})
	joined := strings.Join(args, "\n")

	for _, want := range []string{
		"scan",
		"--export=/data/report",
		"--export-tar=/data/report.tar.gz",
		"--hold",
		"--db-dir=/data/db",
		"--db-auto-update=false",
		"--concurrency=5",
		"--platform=linux/amd64",
		"--scan-timeout=20m0s",
		"--keep-sbom=false",
		"--ecr-auth=false",
		"--log-level=debug",
		"--insecure-skip-tls",
		"--grype-db-direct-download",
		"--ignore-grype-db-unavailable",
		"--namespace=a,b",
		"--customer-name=acme",
		"--cluster-name=prod",
		"--db-ca-cert=" + dbCaCertMountPath,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q:\n%s", want, joined)
		}
	}
	// local-only paths must not leak into the pod
	for _, forbidden := range []string{"/local/ca.pem", "--in-cluster", "--port", "--open", "--openshift"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("args must not contain %q:\n%s", forbidden, joined)
		}
	}
}

func TestScanPodArgsMinimal(t *testing.T) {
	args := scanPodArgs(inClusterOpts{})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--db-auto-update=false",
		"--concurrency=0", // defaulted by the pod itself when 0
		"--ecr-auth=false",
		"--keep-sbom=false",
		"--platform=",
		"--scan-timeout=0s",
		"--log-level=",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q:\n%s", want, joined)
		}
	}
	for _, forbidden := range []string{"--namespace=", "--customer-name=", "--db-ca-cert=", "--insecure", "--grype-db-direct"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("args must not contain %q:\n%s", forbidden, joined)
		}
	}
}

func TestBuildScanPodImagePullPolicy(t *testing.T) {
	for policy, want := range map[string]string{
		"":             "IfNotPresent", // default
		"Always":       "Always",
		"IfNotPresent": "IfNotPresent",
		"Never":        "Never",
	} {
		pod := buildScanPod("img:1", inClusterOpts{ImagePullPolicy: policy}, false)
		if got := string(pod.Spec.Containers[0].ImagePullPolicy); got != want {
			t.Errorf("policy %q: container.ImagePullPolicy = %q, want %q", policy, got, want)
		}
	}
}

func TestParseImagePullPolicy(t *testing.T) {
	for _, ok := range []string{"Always", "IfNotPresent", "Never"} {
		if got, err := parseImagePullPolicy(ok); err != nil || got != ok {
			t.Errorf("parseImagePullPolicy(%q) = %q, %v", ok, got, err)
		}
	}
	for _, bad := range []string{"", "always", "Sometimes", "IfNotPresent "} {
		if _, err := parseImagePullPolicy(bad); err == nil {
			t.Errorf("parseImagePullPolicy(%q): expected error", bad)
		}
	}
}

func TestTarGzRoundtrip(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "report")
	if err := os.MkdirAll(filepath.Join(src, "sbom"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"scan.html":     "<html>report</html>",
		"report.csv":    "a,b,c\n",
		"sbom/img.json": `{"sbom": true}`,
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(src, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	archive := filepath.Join(tmp, "report.tar.gz")
	if err := tarGzDir(src, archive); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(tmp, "extracted")
	if err := tarGzExtract(archive, dest); err != nil {
		t.Fatal(err)
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatalf("extracted %s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestTarGzDirRejectsDestInsideSrc(t *testing.T) {
	tmp := t.TempDir()
	src := filepath.Join(tmp, "report")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tarGzDir(src, filepath.Join(src, "report.tar.gz")); err == nil {
		t.Fatal("expected error for archive destination inside the source dir")
	}
}

func TestTarGzExtractTraversal(t *testing.T) {
	tmp := t.TempDir()
	archive := filepath.Join(tmp, "evil.tar.gz")

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct {
		name string
		data string
	}{
		{"../evil.txt", "nope"},
		{"ok.txt", "fine"},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(tmp, "out")
	if err := tarGzExtract(archive, dest); err == nil {
		t.Fatal("expected error for path traversal entry")
	}
	if _, err := os.Stat(filepath.Join(tmp, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("traversal entry was written outside the destination")
	}
	if _, err := os.Stat(filepath.Join(dest, "ok.txt")); !os.IsNotExist(err) {
		t.Fatal("no files should be extracted after a traversal attempt")
	}
}

func TestDeploymentImagePattern(t *testing.T) {
	m := deploymentImageExtractPattern.FindSubmatch([]byte("      containers:\n        - name: scanner\n          image: ghcr.io/getupcloud/artifactor:0.3.0 # comment\n"))
	if len(m) != 2 || string(m[1]) != "ghcr.io/getupcloud/artifactor:0.3.0" {
		t.Fatalf("image extraction failed: %q", m)
	}
}

func TestPodLogWriter(t *testing.T) {
	var buf bytes.Buffer
	lw := &podLogWriter{w: &buf}

	if lw.since() != nil {
		t.Fatal("initial since should be nil")
	}

	// feed the stream in chunks that split lines mid-way
	chunks := []string{
		"artifactor: 2026/10/31 19:40:07 internal/scanner/scanner.",
		"go:582: scanning 1 SBOM file(s) ...\n",
		"some continuation line\n",
		"artifactor: 2026/10/31 19:40:13 internal/scanner/scanner.go:597: scanning /tmp/sbom.json ...\n",
		"tail without newline",
	}
	for _, c := range chunks {
		if _, err := lw.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}

	if got := buf.String(); got != strings.Join(chunks, "") {
		t.Fatalf("passthrough mismatch:\n%q", got)
	}
	if lw.bytes != int64(len(strings.Join(chunks, ""))) {
		t.Fatalf("bytes = %d", lw.bytes)
	}
	since := lw.since()
	if since == nil {
		t.Fatal("lastTime not recorded")
	}
	if want := "2026/10/31 19:40:13"; since.Format("2006/01/02 15:04:05") != want {
		t.Fatalf("since = %v, want %s", since, want)
	}

	// a line without the logx timestamp must not overwrite lastTime
	if _, err := lw.Write([]byte("no timestamp here\n")); err != nil {
		t.Fatal(err)
	}
	if lw.since().Format("2006/01/02 15:04:05") != "2026/10/31 19:40:13" {
		t.Fatal("lastTime overwritten by a line without timestamp")
	}
}

func TestAskYN(t *testing.T) {
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()

	ask := func(input string) bool {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		os.Stdin = r
		go func() {
			w.WriteString(input)
			w.Close()
		}()
		return askYN("proceed?")
	}
	for input, want := range map[string]bool{
		"y\n":     true,
		"yes\n":   true,
		"Y\n":     true,
		"n\n":     false,
		"\n":      false,
		"maybe\n": false,
	} {
		if got := ask(input); got != want {
			t.Errorf("askYN(%q) = %v, want %v", strings.TrimSpace(input), got, want)
		}
	}
}
