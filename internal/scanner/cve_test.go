package scanner

import (
	"slices"
	"testing"

	"github.com/anchore/grype/grype/match"
	"github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/syft/syft/file"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestCveFromMatchArtifactFields(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:       "CVE-2024-0001",
			Metadata: &vulnerability.Metadata{Severity: "Critical"},
		},
		Package: pkg.Package{
			Name:    "libssl3",
			Version: "3.0.11",
			Type:    syftPkg.DebPkg,
			PURL:    "pkg:deb/debian/libssl3@3.0.11?arch=amd64",
			Locations: file.NewLocationSet(
				file.NewLocation("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"),
				file.NewVirtualLocation("/usr/lib/x86_64-linux-gnu/libssl.so.3", "/usr/lib/x86_64-linux-gnu/libssl.so.3"),
				file.NewLocation("/usr/lib/x86_64-linux-gnu/libcrypto.so.3"), // duplicate
			),
		},
	}
	c := cveFromMatch(m)
	if c.PURL != "pkg:deb/debian/libssl3@3.0.11?arch=amd64" {
		t.Errorf("purl = %q", c.PURL)
	}
	want := []CVEArtifactLocation{
		{Path: "/usr/lib/x86_64-linux-gnu/libcrypto.so.3", Kind: "package"},
		{Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3", Kind: "package"},
	}
	if !slices.Equal(c.Locations, want) {
		t.Errorf("locations = %+v, want %+v", c.Locations, want)
	}
}

func TestLocationKind(t *testing.T) {
	cases := map[syftPkg.Type]string{
		syftPkg.ApkPkg:                "package",
		syftPkg.DebPkg:                "package",
		syftPkg.RpmPkg:                "package",
		syftPkg.AlpmPkg:               "package",
		syftPkg.PortagePkg:            "package",
		syftPkg.BinaryPkg:             "filename",
		syftPkg.JavaPkg:               "filename",
		syftPkg.JenkinsPluginPkg:      "filename",
		syftPkg.LinuxKernelPkg:        "filename",
		syftPkg.LinuxKernelModulePkg:  "filename",
		syftPkg.GraalVMNativeImagePkg: "filename",
		syftPkg.ModelPkg:              "filename",
		syftPkg.PythonPkg:             "metadata",
		syftPkg.CondaPkg:              "metadata",
		syftPkg.Rpkg:                  "metadata",
		syftPkg.NpmPkg:                "path",
		syftPkg.GoModulePkg:           "path",
		syftPkg.GemPkg:                "path",
		syftPkg.RustPkg:               "path",
		syftPkg.UnknownPkg:            "path",
	}
	for typ, want := range cases {
		if got := locationKind(typ); got != want {
			t.Errorf("locationKind(%q) = %q, want %q", typ, got, want)
		}
	}
}

func TestCveFromMatchNoArtifact(t *testing.T) {
	m := match.Match{
		Vulnerability: vulnerability.Vulnerability{
			ID:       "CVE-2024-0002",
			Metadata: &vulnerability.Metadata{Severity: "Medium"},
		},
		Package: pkg.Package{Name: "nginx", Version: "1.25.3"},
	}
	c := cveFromMatch(m)
	if c.PURL != "" {
		t.Errorf("purl = %q, want empty", c.PURL)
	}
	if len(c.Locations) != 0 {
		t.Errorf("locations = %v, want none", c.Locations)
	}
}
