package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CI workflow and the Makefile targets are part of the development
// contract: a broken unit test or an unformatted file must fail the build
// before it reaches main, and the checks that run in CI must be the same ones
// a contributor runs locally. These tests keep the two in sync.

// testWorkflowPath is the workflow that runs the checks on every pull request
// and on every push to main.
const testWorkflowPath = ".github/workflows/test.yaml"

// makeRecipe returns the recipe of a Makefile target: the tab-indented lines
// that follow the "<target>:" line, without the leading tab.
func makeRecipe(t *testing.T, makefile, target string) string {
	t.Helper()

	var (
		inRecipe bool
		lines    []string
	)
	for _, line := range strings.Split(makefile, "\n") {
		if !inRecipe {
			if strings.HasPrefix(line, target+":") {
				inRecipe = true
			}
			continue
		}
		// A recipe ends at the first line that is not tab-indented.
		if !strings.HasPrefix(line, "\t") {
			break
		}
		lines = append(lines, strings.TrimSpace(line))
	}
	if len(lines) == 0 {
		t.Fatalf("Makefile target %q not found (or it has no recipe)", target)
	}
	return strings.Join(lines, "\n")
}

func readMakefile(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile("Makefile")
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	return string(content)
}

func readTestWorkflow(t *testing.T) string {
	t.Helper()
	content, err := os.ReadFile(filepath.FromSlash(testWorkflowPath))
	if err != nil {
		t.Fatalf("read %s: %v", testWorkflowPath, err)
	}
	return string(content)
}

// TestMakeTestUsesRaceDetector pins the `make test` command: local runs must
// use the race detector and ignore the Go test cache, exactly like CI.
func TestMakeTestUsesRaceDetector(t *testing.T) {
	recipe := makeRecipe(t, readMakefile(t), "test")

	tests := []struct {
		name string
		want string
	}{
		{"runs the tests", "go test"},
		{"with the race detector", "-race"},
		{"ignoring the test cache", "-count=1"},
		{"on every package", "./..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(recipe, tt.want) {
				t.Errorf("`make test` recipe %q does not contain %q", recipe, tt.want)
			}
		})
	}
}

// TestTestWorkflowChecksFormatting checks the gofmt gate: it must list the
// offending files and fail the step.
func TestTestWorkflowChecksFormatting(t *testing.T) {
	workflow := readTestWorkflow(t)

	tests := []struct {
		name string
		want string
	}{
		{"lists the unformatted files", "gofmt -l ."},
		{"fails the step", "exit 1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(workflow, tt.want) {
				t.Errorf("%s does not contain %q", testWorkflowPath, tt.want)
			}
		})
	}
}

// TestTestWorkflowTriggers checks that the workflow runs on the events the
// issue requires: every pull request and every push to main.
func TestTestWorkflowTriggers(t *testing.T) {
	workflow := readTestWorkflow(t)

	tests := []struct {
		name string
		want string
	}{
		{"every pull request", "pull_request:"},
		{"pushes to main", "branches: [main]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(workflow, tt.want) {
				t.Errorf("%s does not contain %q", testWorkflowPath, tt.want)
			}
		})
	}
}

// TestTestWorkflowRunsTheMakeTargets requires every command of the `vet` and
// `test` targets to appear verbatim in the workflow, so a change to one of
// them without the other is caught by the test suite instead of in a pull
// request.
func TestTestWorkflowRunsTheMakeTargets(t *testing.T) {
	makefile := readMakefile(t)
	workflow := readTestWorkflow(t)

	for _, target := range []string{"vet", "test"} {
		t.Run(target, func(t *testing.T) {
			for _, command := range strings.Split(makeRecipe(t, makefile, target), "\n") {
				if command == "" {
					continue
				}
				if !strings.Contains(workflow, command) {
					t.Errorf("%s does not run the `make %s` command %q", testWorkflowPath, target, command)
				}
			}
		})
	}
}
