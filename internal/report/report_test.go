package report

import (
	"bytes"
	"github.com/harinaralasetty/underhood/internal/model"
	"github.com/harinaralasetty/underhood/internal/target"
	"strings"
	"testing"
)

func TestMergeSummaryAndRendering(t *testing.T) {
	ev := model.Evidence{File: "Contents/test", Locator: "key", Value: "<value>|`raw`"}
	r := target.Result{Findings: []model.Finding{{ID: "ent.no-sandbox@a", Category: "entitlements", Title: "App Sandbox not enabled", Severity: model.Sensitive, Evidence: []model.Evidence{ev}}, {ID: "ent.no-sandbox@a", Category: "entitlements", Evidence: []model.Evidence{ev}}, {ID: "missing"}, {ID: "ent.no-sandbox@b", Category: "entitlements", Title: "App Sandbox not enabled", Severity: model.Sensitive, Evidence: []model.Evidence{ev}}}, Skipped: []model.SkipNote{{Analyzer: "x", Reason: "failure", File: "a"}, {Analyzer: "x", Reason: "failure", File: "b"}}}
	rep := Build(r)
	if len(rep.Findings) != 2 || len(rep.Findings[0].Evidence) != 1 || len(rep.Summary) != 1 || len(rep.Summary[0].FindingIDs) != 2 {
		t.Fatal(rep)
	}
	var b bytes.Buffer
	if e := Markdown(&b, rep, false); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(b.String(), "&lt;") || !strings.Contains(b.String(), "<value>") {
		t.Fatal(b.String())
	}
	for _, n := range rep.Skipped {
		if n.Analyzer == "x" && n.Count != 2 {
			t.Fatal(n)
		}
	}
}
