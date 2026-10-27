package main

import (
	"bytes"
	"embed"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"sort"

	flag "github.com/spf13/pflag"
)

// The deploy manifests are embedded in the binary so `artifactor install`
// works from any host without the repository checked out.
//
//go:embed deploy/*.yaml
var manifestsFS embed.FS

var deploymentImagePattern = regexp.MustCompile(`(?m)^(\s+image:\s*)\S+.*$`)

// renderManifests returns the deploy manifests concatenated (separated by
// ---), optionally overriding the container image of the deployment.
func renderManifests(image string) ([]byte, error) {
	entries, err := manifestsFS.ReadDir("deploy")
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var buf bytes.Buffer
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := manifestsFS.ReadFile("deploy/" + entry.Name())
		if err != nil {
			return nil, err
		}
		if image != "" && entry.Name() == "deployment.yaml" {
			data = deploymentImagePattern.ReplaceAll(data, []byte("${1}"+image))
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
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: artifactor %s [--dump] [--image <ref>]\n", action)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(2)
	}

	data, err := renderManifests(*image)
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
