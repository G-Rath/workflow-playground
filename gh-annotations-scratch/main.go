package main

import (
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
)

// cases are hardcoded versions of TestPrintGHAnnotationReport_WithMixedIssues cases
// from internal/output/helpers_test.go, plus the CR sanitization case from
// internal/output/githubannotation_test.go, with groups already built
func cases(cwd string) map[string]*VulnerabilityResults {
	return map[string]*VulnerabilityResults{
		"multiple_sources_with_a_mixed_count_of_packages,_some_called_vulnerabilities_and_license_violations": {
			Results: []PackageSource{
				{
					Source: SourceInfo{Path: cwd + "/path/to/my/first/lockfile"},
					Packages: []PackageVulns{
						{
							Package: PackageInfo{Name: "mine1", Version: "1.2.3"},
							Groups:  []GroupInfo{{IDs: []string{"OSV-1"}, MaxSeverity: "7.8"}},
						},
					},
				},
				{
					Source: SourceInfo{Path: cwd + "/path/to/my/second/lockfile"},
					Packages: []PackageVulns{
						{
							Package: PackageInfo{Name: "mine2", Version: "3.2.5"},
							Groups:  []GroupInfo{{IDs: []string{"OSV-2"}}},
						},
						{
							Package: PackageInfo{Name: "mine3", Version: "0.4.1"},
						},
					},
				},
				{
					Source: SourceInfo{Path: cwd + "/path/to/my/third/lockfile"},
					Packages: []PackageVulns{
						{
							Package: PackageInfo{Name: "mine1", Version: "1.3.5"},
						},
						{
							Package: PackageInfo{Name: "mine1", Version: "1.2.3"},
							Groups:  []GroupInfo{{IDs: []string{"OSV-1"}}},
						},
					},
				},
			},
		},
		"one_source_with_one_deprecated_package": {
			Results: []PackageSource{
				{
					Source: SourceInfo{Path: cwd + "/path/to/lockfile"},
					Packages: []PackageVulns{
						{
							Package: PackageInfo{Name: "deprecated-pkg", Version: "1.0.0", Deprecated: true},
						},
					},
				},
			},
		},
		"cr_sanitization": {
			Results: []PackageSource{
				{
					Source: SourceInfo{Path: "legitimate-scan\r::warning::INJECTED/package-lock.json"},
					Packages: []PackageVulns{
						{
							Package: PackageInfo{Name: "lodash", Version: "4.17.20"},
							Groups:  []GroupInfo{{IDs: []string{"GHSA-35jh-r3h4-6jhm"}, MaxSeverity: "7.2"}},
						},
					},
				},
			},
		},
	}
}

func main() {
	all := cases(mustGetWorkingDirectory())

	names := make([]string, 0, len(all))
	for name := range all {
		names = append(names, name)
	}
	slices.Sort(names)

	caseName := flag.String("case", "all", "case to run, one of: all, "+strings.Join(names, ", "))
	flag.Parse()

	if *caseName != "all" {
		if _, ok := all[*caseName]; !ok {
			fmt.Fprintf(os.Stderr, "unknown case %q\n", *caseName)
			os.Exit(1)
		}
		names = []string{*caseName}
	}

	for _, name := range names {
		if err := PrintGHAnnotationReport(all[name], os.Stdout); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", name, err)
			os.Exit(1)
		}
	}
}
