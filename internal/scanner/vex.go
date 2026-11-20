package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/anchore/grype/grype/vex"
)

// VexDoc is one VEX document participating in the scan: the file path the
// grype processor reads and the name shown to the user and used for the
// per-CVE attribution (basename for --vex paths, upload name for documents
// added via the UI).
type VexDoc struct {
	Path string
	Name string
}

// ResolveVexFiles expands the --vex paths into the final list of VEX
// document files: a regular file contributes itself and a directory
// contributes all of its regular files (non-recursive). Every resulting
// file must exist and be a supported VEX format (OpenVEX or CSAF), checked
// by attempting to build the grype VEX processor for it.
func ResolveVexFiles(paths []string) ([]string, error) {
	files := []string{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("vex path %q: %w", p, err)
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		entries, err := os.ReadDir(p)
		if err != nil {
			return nil, fmt.Errorf("vex directory %q: %w", p, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			files = append(files, filepath.Join(p, e.Name()))
		}
	}
	sort.Strings(files)
	for _, f := range files {
		if _, err := vex.NewProcessor(vex.ProcessorOptions{Documents: []string{f}}); err != nil {
			return nil, fmt.Errorf("vex document %q: %w", f, err)
		}
	}
	return files, nil
}
