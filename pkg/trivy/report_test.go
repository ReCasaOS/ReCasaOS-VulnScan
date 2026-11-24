package trivy

import (
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func count(findings []Finding, severity string) (n int) {
	for _, f := range findings {
		if f.Severity == severity {
			n++
		}
	}

	return n
}

func TestParseCleanImage(t *testing.T) {
	findings, err := Parse(fixture(t, "clean-mailpit.json"))
	if err != nil || len(findings) != 0 {
		t.Fatalf("%d findings, err %v; want none", len(findings), err)
	}
}

// The numbers were counted by hand in the report of vaultwarden/server scanned on 2026-11-23.
func TestParseCritical(t *testing.T) {
	findings, err := Parse(fixture(t, "critical-vaultwarden.json"))
	if err != nil {
		t.Fatal(err)
	}
	if c, h := count(findings, "CRITICAL"), count(findings, "HIGH"); c != 4 || h != 117 {
		t.Fatalf("%d critical, %d high; want 4 and 117", c, h)
	}
	for i, f := range findings {
		if (i < 4) != (f.Severity == "CRITICAL") {
			t.Fatalf("finding %d is %s: the critical ones come first", i, f.Severity)
		}
		if f.ID == "" || f.Package == "" || f.Installed == "" || f.Fixed == "" {
			t.Fatalf("finding %d lacks a field: %+v", i, f)
		}
	}
	if findings[0].ID != "CVE-2026-44172" || !strings.HasPrefix(findings[0].URL, "https://") {
		t.Fatalf("first finding %+v; want CVE-2026-44172 with its link", findings[0])
	}
}

const one = `{"Results":[{"Vulnerabilities":[
 {"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH"}%s]}]}`

func TestParseDropsUnfixed(t *testing.T) {
	findings, err := Parse([]byte(strings.Replace(one, "%s", `,{"VulnerabilityID":"CVE-2","PkgName":"b","InstalledVersion":"1","FixedVersion":"","Severity":"CRITICAL"}`, 1)))
	if err != nil || len(findings) != 1 || findings[0].ID != "CVE-1" {
		t.Fatalf("%+v, err %v; want CVE-1 alone", findings, err)
	}
}

func TestParseDropsOtherSeverity(t *testing.T) {
	extra := ""
	for _, severity := range []string{"MEDIUM", "LOW", "UNKNOWN", "critical", "", "<b>HIGH</b>"} {
		extra += `,{"VulnerabilityID":"CVE-9","PkgName":"` + severity + `x","InstalledVersion":"1","FixedVersion":"2","Severity":"` + severity + `"}`
	}
	findings, err := Parse([]byte(strings.Replace(one, "%s", extra, 1)))
	if err != nil || len(findings) != 1 {
		t.Fatalf("%+v, err %v; want CVE-1 alone", findings, err)
	}
}

func TestParseCountsAPackageOnce(t *testing.T) {
	findings, err := Parse([]byte(strings.Replace(one, "%s", `,{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","FixedVersion":"2","Severity":"HIGH"}`, 1)))
	if err != nil || len(findings) != 1 {
		t.Fatalf("%+v, err %v; want one finding", findings, err)
	}
}

func TestParseBadJSON(t *testing.T) {
	for _, data := range []string{"", "{", "[]", `{"Results":"x"}`} {
		if findings, err := Parse([]byte(data)); err == nil {
			t.Errorf("%q: %+v and no error", data, findings)
		}
	}
}
