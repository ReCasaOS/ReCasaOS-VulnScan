// Package trivy runs the Trivy the archive ships and reads its reports.
package trivy

import (
	"cmp"
	"encoding/json"
	"slices"
)

const (
	Critical = "CRITICAL"
	High     = "HIGH"
)

// Finding is one vulnerability of one package of an image, with the version that fixes it.
type Finding struct {
	ID        string
	Package   string
	Installed string
	Fixed     string
	Severity  string // Critical or High
	Title     string
	URL       string
}

type report struct {
	Results []struct {
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
			PrimaryURL       string
		}
	}
}

// Parse reads a report of `trivy image --format json`. It keeps the critical and high
// vulnerabilities that have a fix, whatever the report was asked to hold, once per package,
// the critical ones first and then by id.
func Parse(data []byte) ([]Finding, error) {
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}

	findings := []Finding{}
	seen := map[[2]string]bool{}
	for _, result := range r.Results {
		for _, v := range result.Vulnerabilities {
			key := [2]string{v.VulnerabilityID, v.PkgName}
			if v.Severity != Critical && v.Severity != High || v.FixedVersion == "" || v.VulnerabilityID == "" || seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, Finding{
				ID: v.VulnerabilityID, Package: v.PkgName, Installed: v.InstalledVersion, Fixed: v.FixedVersion,
				Severity: v.Severity, Title: v.Title, URL: v.PrimaryURL,
			})
		}
	}

	slices.SortFunc(findings, func(a, b Finding) int {
		if a.Severity != b.Severity {
			return cmp.Compare(a.Severity, b.Severity) // CRITICAL sorts before HIGH
		}
		return cmp.Or(cmp.Compare(a.ID, b.ID), cmp.Compare(a.Package, b.Package))
	})

	return findings, nil
}
