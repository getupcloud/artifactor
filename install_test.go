package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderManifests(t *testing.T) {
	data, err := renderManifests("", "", "artifactor", "", "", false, "", false)
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
	// the namespace must be the first manifest
	if strings.Index(text, "kind: Namespace") != strings.Index(text, "kind: ") {
		t.Error("namespace manifest must be rendered first")
	}
}

func TestRenderManifestsNamespace(t *testing.T) {
	data, err := renderManifests("", "", "team-a", "", "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "namespace: artifactor") {
		t.Error("rendered manifests still reference the artifactor namespace")
	}
	if !strings.Contains(text, "namespace: team-a") {
		t.Error("rendered manifests missing namespace: team-a")
	}
	// the Namespace object itself is renamed, resource names are not
	if !strings.Contains(text, "name: team-a") {
		t.Error("namespace.yaml was not renamed to team-a")
	}
	if !strings.Contains(text, "name: artifactor") {
		t.Error("resource names must keep the artifactor prefix")
	}
}

func TestRenderManifestsSkipNamespace(t *testing.T) {
	data, err := renderManifests("", "", "artifactor", "", "", false, "", true)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Contains(text, "kind: Namespace") {
		t.Error("rendered manifests still include the Namespace (uninstall must keep it)")
	}
	for _, want := range []string{"kind: Deployment", "kind: ServiceAccount", "kind: ClusterRole"} {
		if !strings.Contains(text, want) {
			t.Errorf("manifests missing %q", want)
		}
	}
}

func TestRenderManifestsImageOverride(t *testing.T) {
	data, err := renderManifests("registry.example.com/team/artifactor:v9", "", "artifactor", "", "", false, "", false)
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

func TestRenderManifestsNamesEnv(t *testing.T) {
	data, err := renderManifests("", "", "artifactor", "Acme Corp", "prod-eks", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"- name: CUSTOMER_NAME",
		`value: "Acme Corp"`,
		"- name: CLUSTER_NAME",
		`value: "prod-eks"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("deployment env missing %q", want)
		}
	}
	// only DB_CA_CERT remains empty (the CA is configured by --db-ca-cert)
	if got := strings.Count(text, `value: ""`); got != 1 {
		t.Errorf("empty env values after override = %d, want 1 (DB_CA_CERT)", got)
	}

	// unset flags leave the manifest defaults alone
	data, err = renderManifests("", "", "artifactor", "", "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), `value: ""`); got != 3 {
		t.Errorf("default empty env values = %d, want 3 (CUSTOMER_NAME + CLUSTER_NAME + DB_CA_CERT)", got)
	}

	// quotes and backslashes in the value are escaped
	data, err = renderManifests("", "", "artifactor", `Acme "X"\Y`, "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `value: "Acme \"X\"\\Y"`) {
		t.Error("env value was not YAML-escaped")
	}
}

func TestRenderManifestsOpenshift(t *testing.T) {
	// without --openshift the SCC manifests are not rendered
	data, err := renderManifests("", "", "artifactor", "", "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "SecurityContextConstraints") {
		t.Error("OpenShift manifests included without --openshift")
	}

	// with --openshift they are, and the subject namespace follows --namespace
	data, err = renderManifests("", "", "team-a", "", "", true, "", false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"kind: SecurityContextConstraints",
		"name: artifactor-scc",
		"runAsUser:",
		"uid: 65532",
		"securitycontextconstraints",
		"namespace: team-a",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openshift manifests missing %q", want)
		}
	}
	if strings.Contains(text, "namespace: artifactor") {
		t.Error("openshift manifests still reference the artifactor namespace")
	}
}

func TestRenderManifestsDBCACert(t *testing.T) {
	// without the CA data the ConfigMap is not rendered and the deployment
	// keeps the empty DB_CA_CERT env
	data, err := renderManifests("", "", "artifactor", "", "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "kind: ConfigMap") {
		t.Error("DB CA ConfigMap included without caCertData")
	}

	pem := "-----BEGIN CERTIFICATE-----\nMIIBfakecert\n-----END CERTIFICATE-----"
	data, err = renderManifests("", "", "team-a", "", "", false, pem, false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"kind: ConfigMap",
		"name: artifactor-db-ca",
		"namespace: team-a",
		"    -----BEGIN CERTIFICATE-----",
		"    MIIBfakecert",
		`value: "/etc/artifactor/ca/ca.crt"`,
		"- name: db-ca",
		"mountPath: /etc/artifactor/ca",
		"readOnly: true",
		"configMap:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("db-ca manifests missing %q", want)
		}
	}
	if strings.Contains(text, "DB_CA_MOUNT_PLACEHOLDER") || strings.Contains(text, "DB_CA_VOLUME_PLACEHOLDER") {
		t.Error("deployment placeholders not replaced with the CA volume/mount")
	}
}

func TestKubectlArgs(t *testing.T) {
	cases := []struct {
		action string
		dryRun bool
		want   []string
	}{
		{"install", false, []string{"apply", "-f", "-"}},
		{"uninstall", false, []string{"delete", "-f", "-"}},
		{"install", true, []string{"apply", "--dry-run=client", "-f", "-"}},
		{"uninstall", true, []string{"delete", "--dry-run=client", "-f", "-"}},
	}
	for _, c := range cases {
		got := kubectlArgs(c.action, c.dryRun)
		if len(got) != len(c.want) {
			t.Errorf("kubectlArgs(%s, %v) = %v, want %v", c.action, c.dryRun, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("kubectlArgs(%s, %v) = %v, want %v", c.action, c.dryRun, got, c.want)
				break
			}
		}
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
	data, err := renderManifests("", secretData, "artifactor", "", "", false, "", false)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"kind: Secret",
		"name: artifactor-docker-image-token",
		"type: kubernetes.io/dockerconfigjson",
		".dockerconfigjson: " + secretData,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("secret manifest missing %q", want)
		}
	}
	// order: namespace first, then the secret, then the deployment
	nsIdx := strings.Index(text, "kind: Namespace")
	secretIdx := strings.Index(text, "kind: Secret")
	deployIdx := strings.Index(text, "kind: Deployment")
	if !(nsIdx < secretIdx && secretIdx < deployIdx) {
		t.Errorf("manifest order wrong: namespace=%d secret=%d deployment=%d", nsIdx, secretIdx, deployIdx)
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
	if strings.Contains(out, "kind: Namespace") {
		t.Error("uninstall --dump must not delete the namespace")
	}

	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--namespace", "team-a"})
	})
	if !strings.Contains(out, "namespace: team-a") || strings.Contains(out, "namespace: artifactor") {
		t.Error("install --dump --namespace did not rewrite the manifests")
	}
	if !strings.Contains(out, "name: team-a") {
		t.Error("install --dump --namespace did not rename the Namespace object")
	}

	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--customer-name", "Acme Corp", "--cluster-name", "prod"})
	})
	if !strings.Contains(out, `value: "Acme Corp"`) || !strings.Contains(out, `value: "prod"`) {
		t.Error("install --dump --customer-name/--cluster-name did not set the deployment env")
	}

	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--openshift"})
	})
	if !strings.Contains(out, "kind: SecurityContextConstraints") || !strings.Contains(out, "name: artifactor-scc") {
		t.Error("install --dump --openshift did not include the SCC manifests")
	}

	pemFile := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(pemFile, []byte("-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----"), 0o644); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--db-ca-cert", pemFile})
	})
	if !strings.Contains(out, "kind: ConfigMap") || !strings.Contains(out, "name: artifactor-db-ca") ||
		!strings.Contains(out, "    FAKECERT") || !strings.Contains(out, `value: "/etc/artifactor/ca/ca.crt"`) {
		t.Error("install --dump --db-ca-cert did not embed the CA ConfigMap and configure the deployment")
	}

	t.Setenv("GH_TOKEN", "tok123")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env"})
	})
	if !strings.Contains(out, "kind: Secret") {
		t.Error("install --dump --image-token-env did not include the secret")
	}
	if !strings.Contains(out, "name: artifactor-docker-image-token") {
		t.Error("install --dump --image-token-env missing artifactor-docker-image-token secret")
	}
	secretData, _ := dockerConfigSecretData("tok123")
	if !strings.Contains(out, ".dockerconfigjson: "+secretData) {
		t.Error("install --dump --image-token-env did not use GH_TOKEN")
	}

	// GH_TOKEN takes precedence over GITHUB_TOKEN
	t.Setenv("GITHUB_TOKEN", "tok999")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env"})
	})
	if strings.Contains(out, ".dockerconfigjson: "+mustSecretData(t, "tok999")) {
		t.Error("GITHUB_TOKEN overrode GH_TOKEN")
	}

	// falls back to GITHUB_TOKEN when GH_TOKEN is unset
	os.Unsetenv("GH_TOKEN")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env"})
	})
	if !strings.Contains(out, ".dockerconfigjson: "+mustSecretData(t, "tok999")) {
		t.Error("install --dump --image-token-env did not fall back to GITHUB_TOKEN")
	}

	t.Setenv("MY_TOKEN", "tok456")
	out = captureStdout(t, func() {
		runInstallCmd("install", []string{"--dump", "--image-token-env=MY_TOKEN"})
	})
	if !strings.Contains(out, ".dockerconfigjson: "+mustSecretData(t, "tok456")) {
		t.Error("install --dump --image-token-env=MY_TOKEN did not use MY_TOKEN")
	}
}

func mustSecretData(t *testing.T, token string) string {
	t.Helper()
	s, err := dockerConfigSecretData(token)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOpenFile(t *testing.T) {
	// command without ${FILE}: the file path is appended as last argument
	if err := openFile("true", "/tmp/x"); err != nil {
		t.Fatalf("openFile(true): %v", err)
	}
	// ${FILE} is replaced in place
	if err := openFile("echo ${FILE} > /dev/null", "/tmp/x"); err != nil {
		t.Fatalf("openFile(echo): %v", err)
	}
	// empty command errors
	if err := openFile("", "/tmp/x"); err == nil {
		t.Fatal("openFile(empty) should fail")
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
