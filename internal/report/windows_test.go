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
