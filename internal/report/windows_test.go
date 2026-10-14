package report

import (
	"bytes"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
	"strings"
	"testing"
)

func TestWindowsReport(t *testing.T) {
	f := model.Finding{ID: "windows.manifest.requestedExecutionLevel", Category: "windows-manifest", Title: "Requested execution level", Severity: model.Sensitive, Confidence: model.Declared, Evidence: []model.Evidence{{File: ".", Locator: "manifest", Value: "requireAdministrator"}}}
	r := Build(target.Result{Target: model.Target{Kind: "windows-pe"}, Findings: []model.Finding{f}})
	if r.Summary[0].Text != "Requires administrator privileges" {
		t.Fatal(r.Summary)
	}
	for _, full := range []bool{false, true} {
		var b bytes.Buffer
		if e := Markdown(&b, r, full); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(b.String(), "## Windows application manifest") {
			t.Fatal(b.String())
		}
		summary := strings.Split(strings.Split(b.String(), "## Summary")[1], "##")[0]
		if strings.Contains(summary, f.ID) {
			t.Fatal("raw ID in summary")
		}
	}
}

func TestWindowsMixedExecutionLevels(t *testing.T) {
	var findings []model.Finding
	for i, v := range []string{"asInvoker", "requireAdministrator"} {
		sev := model.Info
		if i == 1 {
			sev = model.Sensitive
		}
		findings = append(findings, model.Finding{ID: "windows.manifest.requestedExecutionLevel@" + v, Category: "windows-manifest", Title: "Requested execution level", Severity: sev, Evidence: []model.Evidence{{Value: v}}})
	}
	got := Summary(findings)
	if len(got) != 2 || got[0].Text != "Requires administrator privileges" {
		t.Fatal(got)
	}
}

func TestWindowsMixedResources(t *testing.T) {
	f := model.Finding{ID: "windows.manifest.requestedExecutionLevel", Category: "windows-manifest", Title: "Requested execution level", Severity: model.Sensitive, Evidence: []model.Evidence{{File: ".", Locator: "a", Value: "asInvoker"}, {File: ".", Locator: "b", Value: "requireAdministrator"}}}
	r := Build(target.Result{Target: model.Target{Kind: "windows-pe"}, Findings: []model.Finding{f}})
	if r.Summary[0].Text != "Requires administrator privileges" {
		t.Fatal(r.Summary)
	}
}

func TestMSIXCompactEvidence(t *testing.T) {
	f := model.Finding{ID: "windows.msix.extension.windows.service", Evidence: []model.Evidence{{Locator: "/Extension", Value: "Category=windows.service"}, {Locator: "/Extension/Service", Value: "StartAccount=localSystem"}}}
	if got := compactEvidence(f); !strings.Contains(got.Value, "localSystem") {
		t.Fatal(got)
	}
	f = model.Finding{ID: "windows.msix.signature", Evidence: []model.Evidence{{Locator: "PKCX / SignedData", Value: "PKCS#7"}, {Locator: "signer[0].subject", Value: "CN=Synthetic"}}}
	if got := compactEvidence(f); got.Value != "CN=Synthetic" {
		t.Fatal(got)
	}
	fs := []model.Finding{{ID: "windows.msix.signature", Category: "signing", Severity: model.Info}, {ID: "windows.pe.unsigned@a.exe", Category: "signing", Severity: model.Notable, Title: "Unsigned"}, {ID: "windows.pe.unsigned@b.exe", Category: "signing", Severity: model.Notable, Title: "Unsigned"}}
	s := Summary(fs)
	if len(s) != 1 || !strings.Contains(s[0].Text, "Embedded executable not signed") || len(s[0].FindingIDs) != 2 {
		t.Fatal(s)
	}
}
