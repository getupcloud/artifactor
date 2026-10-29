package main

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"

	flag "github.com/spf13/pflag"
)

// The deploy manifests are embedded in the binary so `artifactor install`
// works from any host without the repository checked out. The
// imagepullsecret.yaml.tmpl template is only included when --image-token-env
// is provided (its .tmpl extension also keeps plain `kubectl apply -f
// deploy/` from applying it).
//
//go:embed deploy/*.yaml deploy/*.yaml.tmpl
var manifestsFS embed.FS

const (
	secretTemplateName    = "imagepullsecret.yaml.tmpl"
	secretPlaceholder     = "__TOKEN_BASE64__"
	openshiftTemplateName = "openshift.yaml.tmpl"
	// Default environment variables read by --image-token-env (in order)
	// when no explicit variable name is given.
	defaultTokenEnvA = "GH_TOKEN"
	defaultTokenEnvB = "GITHUB_TOKEN"
)

var deploymentImagePattern = regexp.MustCompile(`(?m)^(\s+image:\s*)\S+.*$`)

// namespaceFieldPattern matches the namespace field of every namespaced
// manifest (including the subject of the ClusterRoleBinding); resource
// names, labels and the serviceAccountName are deliberately left alone.
var namespaceFieldPattern = regexp.MustCompile(`(?m)^(\s*namespace:\s*)artifactor\s*$`)

// setDeploymentEnv replaces the value of a single env entry of the
// deployment manifest with a double-quoted YAML scalar.
func setDeploymentEnv(data []byte, name, value string) []byte {
	pattern := regexp.MustCompile(`(?m)^(\s+- name: ` + regexp.QuoteMeta(name) + `\n\s+value: ).*$`)
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return pattern.ReplaceAll(data, []byte(`${1}"`+value+`"`))
}

// manifestRank defines the rendering order: the namespace first, then the
// imagePullSecret template (so the secret exists before the deployment that
// references it), then the OpenShift SCC/RBAC manifests (they grant the use
// of the SCC to the service account), then the remaining manifests
// alphabetically.
func manifestRank(name string) int {
	switch name {
	case "namespace.yaml":
		return 0
	case secretTemplateName:
		return 1
	case openshiftTemplateName:
		return 2
	default:
		return 3
	}
}

// dockerConfigSecretData builds the base64-encoded .dockerconfigjson payload
// for the imagePullSecret. A token of the form "user:token" keeps the user
// part; otherwise the user defaults to "gh" (any value works with a PAT on
// ghcr.io).
func dockerConfigSecretData(token string) (string, error) {
	username, password := "gh", token
	if user, pass, ok := strings.Cut(token, ":"); ok {
		username, password = user, pass
	}
	auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	cfg := map[string]any{
		"auths": map[string]any{
			"ghcr.io": map[string]string{"auth": auth},
		},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// renderManifests returns the deploy manifests concatenated (separated by
// ---), optionally overriding the container image of the deployment, the
// namespace of every namespaced manifest, and the CUSTOMER_NAME/CLUSTER_NAME
// env values of the deployment. The imagePullSecret template is included
// only when secretData is non-empty (rendered first, before the deployment
// that references it).
func renderManifests(image, secretData, namespace, customerName, clusterName string, openshift bool) ([]byte, error) {
	entries, err := manifestsFS.ReadDir("deploy")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		ri, rj := manifestRank(entries[i].Name()), manifestRank(entries[j].Name())
		if ri != rj {
			return ri < rj
		}
		return entries[i].Name() < entries[j].Name()
	})

	var buf bytes.Buffer
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		data, err := manifestsFS.ReadFile("deploy/" + entry.Name())
		if err != nil {
			return nil, err
		}
		switch entry.Name() {
		case secretTemplateName:
			if secretData == "" {
				continue
			}
			data = bytes.ReplaceAll(data, []byte(secretPlaceholder), []byte(secretData))
		case openshiftTemplateName:
			if !openshift {
				continue
			}
		case "deployment.yaml":
			if image != "" {
				data = deploymentImagePattern.ReplaceAll(data, []byte("${1}"+image))
			}
			if customerName != "" {
				data = setDeploymentEnv(data, "CUSTOMER_NAME", customerName)
			}
			if clusterName != "" {
				data = setDeploymentEnv(data, "CLUSTER_NAME", clusterName)
			}
		}
		if namespace != "" {
			data = namespaceFieldPattern.ReplaceAll(data, []byte("${1}"+namespace))
			if entry.Name() == "namespace.yaml" {
				data = bytes.ReplaceAll(data, []byte("name: artifactor"), []byte("name: "+namespace))
			}
		}
		buf.Write(bytes.TrimRight(data, "\n"))
		buf.WriteString("\n---\n")
	}
	return buf.Bytes(), nil
}

// runInstallCmd implements the `install` and `uninstall` subcommands.
func runInstallCmd(action string, args []string) {
	fs := flag.NewFlagSet("artifactor "+action, flag.ExitOnError)
	dump := fs.Bool("dump", false, "only print the manifests to stdout without applying them")
	image := fs.String("image", "", "override the container image in the deployment manifest")
	namespace := fs.String("namespace", "artifactor", "namespace to install the manifests into")
	customerName := fs.String("customer-name", "", "set the CUSTOMER_NAME env of the deployment (shown in the execution logs and report title)")
	clusterName := fs.String("cluster-name", "", "set the CLUSTER_NAME env of the deployment (shown in the execution logs and report title)")
	openshift := fs.Bool("openshift", false, "include the OpenShift/OKD SecurityContextConstraints + RBAC manifests (requires cluster-admin to apply)")
	imageTokenEnv := fs.String("image-token-env", "", "read a registry token from this environment variable (default: GH_TOKEN, then GITHUB_TOKEN) and include the artifactor-docker-image-token imagePullSecret manifest")
	fs.Lookup("image-token-env").NoOptDefVal = "auto"
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: artifactor %s [--dump] [--image <ref>] [--namespace <ns>] [--customer-name <name>] [--cluster-name <name>] [--openshift] [--image-token-env[=VAR]]\n", action)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}
	if *namespace == "" {
		log.Fatalf("%s: --namespace cannot be empty", action)
	}

	secretData := ""
	if *imageTokenEnv != "" {
		envNames := []string{*imageTokenEnv}
		if *imageTokenEnv == "auto" {
			envNames = []string{defaultTokenEnvA, defaultTokenEnvB}
		}
		token := ""
		for _, name := range envNames {
			if v := os.Getenv(name); v != "" {
				token = v
				break
			}
		}
		if token == "" {
			log.Fatalf("%s: none of the environment variables %s is set (needed for --image-token-env)", action, strings.Join(envNames, ", "))
		}
		s, err := dockerConfigSecretData(token)
		if err != nil {
			log.Fatalf("%s: build imagePullSecret: %v", action, err)
		}
		secretData = s
	}

	data, err := renderManifests(*image, secretData, *namespace, *customerName, *clusterName, *openshift)
	if err != nil {
		log.Fatalf("%s: render manifests: %v", action, err)
	}
	if *dump {
		_, _ = os.Stdout.Write(data)
		return
	}

	if _, err := exec.LookPath("kubectl"); err != nil {
		log.Fatalf("%s: kubectl not found in PATH (required to apply the manifests; use --dump to print them instead)", action)
	}

	verb := "apply"
	if action == "uninstall" {
		verb = "delete"
	}
	cmd := exec.Command("kubectl", verb, "-f", "-")
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("%s: kubectl %s failed: %v", action, verb, err)
	}
	log.Printf("%s complete", action)
}
